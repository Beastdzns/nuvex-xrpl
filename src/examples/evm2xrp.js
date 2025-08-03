require('dotenv').config();
const xrpl = require('xrpl');
const { ethers } = require('ethers');
const Sdk = require('@1inch/cross-chain-sdk');
const XRPLEscrowClient = require('../client/XRPLEscrowClient');
const { createServer } = require('prool');
const { anvil } = require('prool/instances');
const { randomBytes } = require('ethers');

// Import contract artifacts
const factoryContract = require('../../dist/contracts/TestEscrowFactory.sol/TestEscrowFactory.json');
const resolverContract = require('../../dist/contracts/Resolver.sol/Resolver.json');

// Configuration for EVM → XRPL swap
const config = {
    chain: {
        source: {
            chainId: Sdk.NetworkEnum.ETHEREUM,
            url: process.env.SRC_CHAIN_RPC || 'https://rpc.ankr.com/eth',
            createFork: process.env.SRC_CHAIN_CREATE_FORK !== 'false',
            limitOrderProtocol: '0x111111125421ca6dc452d289314280a0f8842a65',
            wrappedNative: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
            ownerPrivateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
            tokens: {
                USDC: {
                    address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
                    donor: '0xd54F23BE482D9A58676590fCa79c8E43087f92fB'
                }
            }
        }
    },
    xrpl: {
        network: 'wss://s.altnet.rippletest.net:51233'
    },
    nuvex: {
        baseUrl: 'http://localhost:3000'
    }
};

// Test private keys
const userPk = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const resolverPk = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a';

// XRPL utility functions
const xrpUtils = {
    createXRPLWalletFromEthKey: function(ethPrivateKey) {
        const cleanPrivateKey = ethPrivateKey.startsWith('0x') 
            ? ethPrivateKey.slice(2) 
            : ethPrivateKey;
        
        if (!/^[0-9a-fA-F]{64}$/.test(cleanPrivateKey)) {
            throw new Error('Invalid private key format. Must be 64 hex characters.');
        }
        
        const entropy = Buffer.from(cleanPrivateKey, 'hex');
        return xrpl.Wallet.fromEntropy(entropy);
    },

    refuelWalletFromFaucet: async function(wallet, client, minBalance = 5) {
        let xrplClient = client;
        let shouldDisconnect = false;

        try {
            if (!xrplClient) {
                xrplClient = new xrpl.Client(config.xrpl.network);
                await xrplClient.connect();
                shouldDisconnect = true;
            }

            try {
                const response = await xrplClient.request({
                    command: "account_info",
                    account: wallet.address,
                    ledger_index: "validated"
                });
                
                const currentBalance = Number(xrpl.dropsToXrp(response.result.account_data.Balance));
                console.log(`💰 Wallet ${wallet.address} current balance: ${currentBalance} XRP`);
                
                if (currentBalance >= minBalance) {
                    console.log(`✅ Wallet ${wallet.address} has sufficient balance, skipping funding`);
                    return;
                }
            } catch (error) {
                console.log(`🆕 Wallet ${wallet.address} account not found, proceeding with funding`);
            }

            console.log(`💸 Funding wallet ${wallet.address} from testnet faucet...`);
            await xrplClient.fundWallet(wallet);
            console.log(`✅ Successfully funded wallet ${wallet.address}`);
        } catch (error) {
            throw new Error(`Failed to fund wallet ${wallet.address}: ${error.message}`);
        } finally {
            if (shouldDisconnect && xrplClient) {
                await xrplClient.disconnect();
            }
        }
    },

    sendXRP: async function(fromWallet, toAddress, amount, client) {
        let xrplClient = client;
        let shouldDisconnect = false;

        try {
            if (!xrplClient) {
                xrplClient = new xrpl.Client(config.xrpl.network);
                await xrplClient.connect();
                shouldDisconnect = true;
            }

            const amountStr = typeof amount === 'number' ? amount.toString() : amount;

            const payment = {
                TransactionType: 'Payment',
                Account: fromWallet.address,
                Destination: toAddress,
                Amount: amountStr
            };

            console.log(`🌊 Sending ${amountStr} XRP drops from ${fromWallet.address} to ${toAddress}...`);

            const response = await xrplClient.submitAndWait(payment, { wallet: fromWallet });
            
            if (response.result.validated && response.result.meta && 
                typeof response.result.meta === 'object' && 'TransactionResult' in response.result.meta) {
                if (response.result.meta.TransactionResult === 'tesSUCCESS') {
                    console.log(`✅ Successfully sent ${amountStr} XRP drops. Transaction hash: ${response.result.hash}`);
                    return response.result.hash;
                } else {
                    throw new Error(`Transaction failed: ${response.result.meta.TransactionResult}`);
                }
            } else {
                throw new Error(`Transaction validation failed or incomplete response`);
            }
        } catch (error) {
            throw new Error(`Failed to send XRP from ${fromWallet.address} to ${toAddress}: ${error.message}`);
        } finally {
            if (shouldDisconnect && xrplClient) {
                await xrplClient.disconnect();
            }
        }
    }
};

// EVM Wallet implementation
class Wallet {
    constructor(privateKeyOrSigner, provider) {
        this.provider = provider;
        this.signer = typeof privateKeyOrSigner === 'string'
            ? new ethers.Wallet(privateKeyOrSigner, this.provider)
            : privateKeyOrSigner;
    }

    static async fromAddress(address, provider) {
        await provider.send('anvil_impersonateAccount', [address.toString()]);
        const signer = await provider.getSigner(address.toString());
        return new Wallet(signer, provider);
    }

    async tokenBalance(token) {
        const tokenContract = new ethers.Contract(token.toString(), [
            'function balanceOf(address) view returns (uint256)'
        ], this.provider);
        return tokenContract.balanceOf(await this.getAddress());
    }

    async topUpFromDonor(token, donor, amount) {
        const donorWallet = await Wallet.fromAddress(donor, this.provider);
        await donorWallet.transferToken(token, await this.getAddress(), amount);
    }

    async getAddress() {
        return this.signer.getAddress();
    }

    async unlimitedApprove(tokenAddress, spender) {
        const currentApprove = await this.getAllowance(tokenAddress, spender);
        if (currentApprove !== 0n) {
            await this.approveToken(tokenAddress, spender, 0n);
        }
        await this.approveToken(tokenAddress, spender, ethers.MaxUint256);
    }

    async getAllowance(token, spender) {
        const contract = new ethers.Contract(token.toString(), [
            'function allowance(address,address) view returns (uint256)'
        ], this.provider);
        return contract.allowance(await this.getAddress(), spender.toString());
    }

    async transfer(dest, amount) {
        await this.signer.sendTransaction({
            to: dest,
            value: amount
        });
    }

    async transferToken(token, dest, amount) {
        const tx = await this.signer.sendTransaction({
            to: token.toString(),
            data: '0xa9059cbb' + ethers.AbiCoder.defaultAbiCoder()
                .encode(['address', 'uint256'], [dest.toString(), amount]).slice(2)
        });
        await tx.wait();
    }

    async approveToken(token, spender, amount) {
        const tx = await this.signer.sendTransaction({
            to: token.toString(),
            data: '0x095ea7b3' + ethers.AbiCoder.defaultAbiCoder()
                .encode(['address', 'uint256'], [spender.toString(), amount]).slice(2)
        });
        await tx.wait();
    }

    async signOrder(srcChainId, order) {
        const typedData = order.getTypedData(srcChainId);
        return this.signer.signTypedData(
            typedData.domain,
            {Order: typedData.types[typedData.primaryType]},
            typedData.message
        );
    }

    async send(param) {
        const res = await this.signer.sendTransaction({
            ...param, 
            gasLimit: 10_000_000, 
            from: await this.getAddress()
        });
        const receipt = await res.wait(1);

        if (receipt && receipt.status) {
            const block = await this.provider.getBlock(receipt.blockNumber);
            return {
                txHash: receipt.hash,
                blockTimestamp: BigInt(block.timestamp),
                blockHash: receipt.blockHash
            };
        }
        throw new Error('Transaction failed');
    }
}

// Resolver implementation
class Resolver {
    constructor(srcAddress, dstAddress) {
        this.srcAddress = srcAddress;
        this.dstAddress = dstAddress;
        this.iface = new ethers.Interface(resolverContract.abi);
    }

    deploySrc(srcChainId, order, signature, takerTraits, fillAmount) {
        const {r, yParityAndS: vs} = ethers.Signature.from(signature);
        const {args, trait} = takerTraits.encode();
        const immutables = order.toSrcImmutables(
            srcChainId, 
            new Sdk.Address(this.srcAddress), 
            fillAmount, 
            order.escrowExtension.hashLockInfo
        );

        return {
            to: this.srcAddress,
            data: this.iface.encodeFunctionData('deploySrc', [
                immutables.build(),
                order.build(),
                r,
                vs,
                fillAmount,
                trait,
                args
            ]),
            value: order.escrowExtension.srcSafetyDeposit
        };
    }

    withdraw(side, escrow, secret, immutables) {
        return {
            to: side === 'src' ? this.srcAddress : this.dstAddress,
            data: this.iface.encodeFunctionData('withdraw', [
                escrow.toString(), 
                secret, 
                immutables.build()
            ])
        };
    }

    cancel(side, escrow, immutables) {
        return {
            to: side === 'src' ? this.srcAddress : this.dstAddress,
            data: this.iface.encodeFunctionData('cancel', [
                escrow.toString(), 
                immutables.build()
            ])
        };
    }
}

// EscrowFactory implementation
class EscrowFactory {
    constructor(provider, address) {
        this.provider = provider;
        this.address = address;
        this.iface = new ethers.Interface(factoryContract.abi);
    }

    async getSourceImpl() {
        return Sdk.Address.fromBigInt(
            BigInt(await this.provider.call({
                to: this.address,
                data: ethers.id('ESCROW_SRC_IMPLEMENTATION()').slice(0, 10)
            }))
        );
    }

    async getSrcDeployEvent(blockHash) {
        const event = this.iface.getEvent('SrcEscrowCreated');
        const logs = await this.provider.getLogs({
            blockHash,
            address: this.address,
            topics: [event.topicHash]
        });

        console.log(`DEBUG: Found ${logs.length} SrcEscrowCreated logs`);

        if (logs.length === 0) {
            return [];
        }

        const [data] = logs.map((l) => this.iface.decodeEventLog(event, l.data));
        const immutables = data.at(0);
        const complement = data.at(1);

        console.log('DEBUG: immutables:', immutables);
        console.log('DEBUG: complement:', complement);

        return [
            Sdk.Immutables.new({
                orderHash: immutables[0],
                hashLock: Sdk.HashLock.fromString(immutables[1]),
                maker: Sdk.Address.fromBigInt(immutables[2]),
                taker: Sdk.Address.fromBigInt(immutables[3]),
                token: Sdk.Address.fromBigInt(immutables[4]),
                amount: immutables[5],
                safetyDeposit: immutables[6],
                timeLocks: Sdk.TimeLocks.fromBigInt(immutables[7])
            }),
            Sdk.DstImmutablesComplement.new({
                maker: Sdk.Address.fromBigInt(complement[0]),
                amount: complement[1],
                token: Sdk.Address.fromBigInt(complement[2]),
                safetyDeposit: complement[3]
            })
        ];
    }
}

// Helper functions for fork setup
async function getProvider(cnf) {
    if (!cnf.createFork) {
        return {
            provider: new ethers.JsonRpcProvider(cnf.url, cnf.chainId, {
                cacheTimeout: -1,
                staticNetwork: true
            })
        };
    }

    const node = createServer({
        instance: anvil({forkUrl: cnf.url, chainId: cnf.chainId}),
        limit: 1
    });
    await node.start();

    const address = node.address();
    const provider = new ethers.JsonRpcProvider(
        `http://[${address.address}]:${address.port}/1`, 
        cnf.chainId, 
        {
            cacheTimeout: -1,
            staticNetwork: true
        }
    );

    return { provider, node };
}

async function deploy(json, params, provider, deployer) {
    const deployed = await new ethers.ContractFactory(json.abi, json.bytecode, deployer)
        .deploy(...params);
    await deployed.waitForDeployment();
    return await deployed.getAddress();
}

async function initChain(cnf) {
    const {node, provider} = await getProvider(cnf);
    const deployer = new ethers.Wallet(cnf.ownerPrivateKey, provider);

    // Deploy EscrowFactory
    const escrowFactory = await deploy(
        factoryContract,
        [
            cnf.limitOrderProtocol,
            cnf.wrappedNative,
            ethers.ZeroAddress, // accessToken
            deployer.address, // owner
            60 * 30, // src rescue delay
            60 * 30 // dst rescue delay
        ],
        provider,
        deployer
    );
    console.log(`[${cnf.chainId}] Escrow factory contract deployed to`, escrowFactory);

    // Deploy Resolver contract
    const resolver = await deploy(
        resolverContract,
        [
            escrowFactory,
            cnf.limitOrderProtocol,
            ethers.computeAddress(resolverPk) // resolver as owner of contract
        ],
        provider,
        deployer
    );
    console.log(`[${cnf.chainId}] Resolver contract deployed to`, resolver);

    return {node, provider, resolver, escrowFactory};
}

/**
 * Real EVM → XRPL Cross-Chain Atomic Swap Implementation
 * 
 * This implementation demonstrates:
 * 1. User has USDC on Ethereum (source)
 * 2. User wants XRP on XRPL (destination)
 * 3. Resolver provides XRP liquidity on XRPL
 * 4. Resolver gets USDC on Ethereum
 * 5. Uses hash-locked atomic swaps for security
 */
class EVMToXRPLSwap {
    constructor() {
        this.xrplClient = null;
        this.nuvexClient = null;
        this.src = null;
        this.srcChainUser = null;
        this.srcChainResolver = null;
        this.srcFactory = null;
        this.srcResolverContract = null;
        this.resolver = null;
        this.userXRPLWallet = null;
        this.resolverXRPLWallet = null;
    }

    async initialize() {
        console.log('🚀 Initializing Real EVM → XRPL Cross-Chain Swap');
        console.log('===============================================\n');

        // Initialize source chain with fork infrastructure
        console.log('🔗 Setting up Ethereum fork...');
        this.src = await initChain(config.chain.source);
        console.log('✅ Ethereum fork initialized\n');

        // Create wallets for EVM chain
        this.srcChainUser = new Wallet(userPk, this.src.provider);
        this.srcChainResolver = new Wallet(resolverPk, this.src.provider);

        // Initialize escrow factory
        this.srcFactory = new EscrowFactory(this.src.provider, this.src.escrowFactory);

        // Set up USDC for user in source chain (user starts with USDC, wants XRP)
        console.log('💰 Setting up initial USDC balance for user...');
        await this.srcChainUser.topUpFromDonor(
            config.chain.source.tokens.USDC.address,
            config.chain.source.tokens.USDC.donor,
            ethers.parseUnits('1000', 6)
        );
        await this.srcChainUser.unlimitedApprove(
            config.chain.source.tokens.USDC.address,
            config.chain.source.limitOrderProtocol
        );

        // Set up resolver contract wallet
        this.srcResolverContract = await Wallet.fromAddress(this.src.resolver, this.src.provider);
        
        console.log('✅ USDC balances configured\n');

        // Initialize resolver
        this.resolver = new Resolver(this.src.resolver, ethers.ZeroAddress);

        // Initialize XRPL
        console.log('🌊 Connecting to XRPL testnet...');
        this.xrplClient = new xrpl.Client(config.xrpl.network);
        await this.xrplClient.connect();

        // User will receive XRP, resolver will provide XRP
        this.userXRPLWallet = xrpUtils.createXRPLWalletFromEthKey(userPk);
        this.resolverXRPLWallet = xrpUtils.createXRPLWalletFromEthKey(resolverPk);

        await xrpUtils.refuelWalletFromFaucet(this.userXRPLWallet, this.xrplClient);
        await xrpUtils.refuelWalletFromFaucet(this.resolverXRPLWallet, this.xrplClient);
        console.log('✅ XRPL wallets funded\n');

        // Initialize Nuvex client
        this.nuvexClient = new XRPLEscrowClient({ baseUrl: config.nuvex.baseUrl });
        console.log('✅ Nuvex client initialized\n');

        console.log(`📝 User EVM: ${await this.srcChainUser.getAddress()}`);
        console.log(`📝 User XRPL: ${this.userXRPLWallet.address} (will receive XRP)`);
        console.log(`📝 Resolver EVM: ${await this.srcChainResolver.getAddress()}`);
        console.log(`📝 Resolver XRPL: ${this.resolverXRPLWallet.address} (provides XRP)\n`);

        // Check initial balances
        const userUSDCBalance = await this.srcChainUser.tokenBalance(config.chain.source.tokens.USDC.address);
        console.log(`💰 User initial USDC balance: ${ethers.formatUnits(userUSDCBalance, 6)} USDC`);
        
        const userXRPResponse = await this.xrplClient.request({
            command: "account_info",
            account: this.userXRPLWallet.address
        });
        const userXRPBalance = Number(xrpl.dropsToXrp(userXRPResponse.result.account_data.Balance));
        console.log(`💰 User initial XRP balance: ${userXRPBalance} XRP\n`);
    }

    async executeSwap() {
        console.log('🔄 Starting EVM → XRPL Atomic Swap');
        console.log('==================================\n');

        // 1. Create cross-chain order (User wants to trade USDC for XRP)
        const secret = ethers.hexlify(randomBytes(32));
        console.log(`🔐 Generated secret: ${secret}`);

        const srcTimestamp = BigInt((await this.src.provider.getBlock('latest')).timestamp);
        
        const order = Sdk.CrossChainOrder.new(
            new Sdk.Address(this.src.escrowFactory),
            {
                salt: Sdk.randBigInt(1000n),
                maker: new Sdk.Address(await this.srcChainUser.getAddress()),
                makingAmount: ethers.parseUnits('10', 6), // User offers 10 USDC
                takingAmount: ethers.parseUnits('5', 6), // User wants equivalent of 5 XRP (in drops representation)
                makerAsset: new Sdk.Address(config.chain.source.tokens.USDC.address),
                takerAsset: new Sdk.Address("0x0000000000000000000000000000000000000000") // XRP (represented as native token)
            },
            {
                hashLock: Sdk.HashLock.forSingleFill(secret),
                timeLocks: Sdk.TimeLocks.new({
                    srcWithdrawal: 10n,      // 10sec finality lock
                    srcPublicWithdrawal: 120n, // 2m for private withdrawal  
                    srcCancellation: 121n,   // 1sec public withdrawal
                    srcPublicCancellation: 122n, // 1sec private cancellation
                    dstWithdrawal: 10n,      // 10sec finality lock
                    dstPublicWithdrawal: 100n, // 100sec private withdrawal
                    dstCancellation: 101n    // 1sec public withdrawal
                }),
                srcChainId: config.chain.source.chainId,
                dstChainId: Sdk.NetworkEnum.BINANCE, // Use BSC as placeholder for XRPL
                srcSafetyDeposit: ethers.parseUnits('0.1', 6),
                dstSafetyDeposit: ethers.parseUnits('0.1', 6)
            },
            {
                auction: new Sdk.AuctionDetails({
                    initialRateBump: 0,
                    points: [],
                    duration: 120n,
                    startTime: srcTimestamp
                }),
                whitelist: [
                    {
                        address: new Sdk.Address(this.src.resolver),
                        allowFrom: 0n
                    }
                ],
                resolvingStartTime: 0n
            },
            {
                nonce: Sdk.randBigInt(BigInt('0xffffffffff')),
                allowPartialFills: false,
                allowMultipleFills: false
            }
        );

        const signature = await this.srcChainUser.signOrder(config.chain.source.chainId, order);
        const orderHash = order.getOrderHash(config.chain.source.chainId);
        console.log(`📋 Order created: ${orderHash}\n`);

        // 2. Resolver fills order and deploys source escrow (locks user's USDC)
        console.log('🏗️  Resolver filling order and deploying source escrow...');
        const fillAmount = order.makingAmount;
        const {txHash: orderFillHash, blockHash: srcDeployBlock} = await this.srcChainResolver.send(
            this.resolver.deploySrc(
                config.chain.source.chainId,
                order,
                signature,
                Sdk.TakerTraits.default()
                    .setExtension(order.extension)
                    .setAmountMode(Sdk.AmountMode.maker)
                    .setAmountThreshold(order.takingAmount),
                fillAmount
            )
        );
        console.log(`✅ Source escrow deployed, order filled: ${orderFillHash}\n`);

        // Debug: Check all events in the transaction receipt
        const receipt = await this.src.provider.getTransactionReceipt(orderFillHash);
        console.log('DEBUG: All events in transaction:', receipt.logs.length);
        
        receipt.logs.forEach((log, i) => {
            console.log(`DEBUG: Event ${i}:`, {
                address: log.address,
                topics: log.topics.slice(0, 2), // Just show first 2 topics for brevity
                data: log.data.slice(0, 100) + '...' // Truncate data
            });
        });

        const srcEscrowEvent = await this.srcFactory.getSrcDeployEvent(srcDeployBlock);
        console.log('DEBUG: srcEscrowEvent length:', srcEscrowEvent.length);
        console.log('DEBUG: srcEscrowEvent[0]:', srcEscrowEvent[0]);
        
        // 3. Create XRPL escrow (where resolver will lock XRP for user)
        console.log('🌊 Creating XRPL escrow...');
        
        const createEscrowPayload = {
            orderHash,
            hashlock: order.escrowExtension.hashLockInfo.toString(),
            maker: this.resolverXRPLWallet.address.toString(), // Resolver provides XRP
            taker: this.userXRPLWallet.address.toString(),     // User receives XRP
            token: "0x0000000000000000000000000000000000000000", // Native XRP
            amount: '5000000', // 5 XRP in drops
            safetyDeposit: '100000', // 0.1 XRP in drops
            timelocks: order.escrowExtension.timeLocks.build().toString(),
            type: 'dst'
        };

        const xrpEscrow = await this.nuvexClient.createDestinationEscrow(createEscrowPayload);
        console.log(`✅ XRPL escrow created: ${xrpEscrow.escrowId}\n`);

        // 4. Resolver funds XRPL escrow (provides XRP liquidity)
        console.log('💰 Resolver funding XRPL escrow with XRP...');
        const resolverDepositHash = await xrpUtils.sendXRP(
            this.resolverXRPLWallet, 
            xrpEscrow.walletAddress, 
            xrpEscrow.requiredDeposit.xrp,
            this.xrplClient
        );
        
        await this.nuvexClient.fundEscrow(xrpEscrow.escrowId, {
            fromAddress: this.resolverXRPLWallet.address,
            txHash: resolverDepositHash
        });
        
        console.log(`✅ XRPL escrow funded by resolver`);
        console.log(`🔗 Deposit TX: https://testnet.xrpl.org/transactions/${resolverDepositHash}\n`);

        // 5. Wait for timelock window
        console.log('⏳ Waiting for withdrawal timelock...');
        await new Promise(resolve => setTimeout(resolve, 11000)); // Wait 11 seconds
        
        // 6. User withdraws XRP from XRPL escrow (reveals secret)
        console.log('🎯 User withdrawing XRP from XRPL escrow...');
        const xrplWithdrawal = await this.nuvexClient.withdraw(
            xrpEscrow.escrowId, 
            secret, 
            this.userXRPLWallet.address,
            false // User withdrawal, not resolver
        );
        
        console.log(`✅ User successfully withdrew XRP`);
        console.log(`🔗 Withdrawal TX: https://testnet.xrpl.org/transactions/${xrplWithdrawal.txHash}\n`);

        // 7. Resolver uses revealed secret to withdraw USDC from source escrow
        console.log('💰 Resolver withdrawing USDC from source escrow...');
        const ESCROW_SRC_IMPLEMENTATION = await this.srcFactory.getSourceImpl();
        const srcEscrowAddress = new Sdk.EscrowFactory(new Sdk.Address(this.src.escrowFactory))
            .getSrcEscrowAddress(srcEscrowEvent[0], ESCROW_SRC_IMPLEMENTATION);

        const {txHash: resolverWithdrawHash} = await this.srcChainResolver.send(
            this.resolver.withdraw('src', srcEscrowAddress, secret, srcEscrowEvent[0])
        );
        
        console.log(`✅ Resolver successfully withdrew USDC: ${resolverWithdrawHash}\n`);

        // 8. Verify final balances
        console.log('🔍 Verifying final balances...');
        const finalUserUSDC = await this.srcChainUser.tokenBalance(config.chain.source.tokens.USDC.address);
        const finalResolverUSDC = await this.srcResolverContract.tokenBalance(config.chain.source.tokens.USDC.address);
        
        const finalUserXRPResponse = await this.xrplClient.request({
            command: "account_info",
            account: this.userXRPLWallet.address
        });
        const finalUserXRP = Number(xrpl.dropsToXrp(finalUserXRPResponse.result.account_data.Balance));

        console.log(`📊 Final user USDC balance: ${ethers.formatUnits(finalUserUSDC, 6)} USDC`);
        console.log(`📊 Final user XRP balance: ${finalUserXRP} XRP`);
        console.log(`📊 Resolver gained USDC: ${ethers.formatUnits(finalResolverUSDC, 6)} USDC`);

        console.log('\n🎉 EVM → XRPL Cross-Chain Swap Complete!');
        console.log('=======================================');
        console.log(`📋 Order Hash: ${orderHash}`);
        console.log(`🔐 Secret: ${secret}`);
        console.log(`🌊 XRPL Escrow: ${xrpEscrow.escrowId}`);
        console.log(`💱 Swap: 10 USDC → 5 XRP`);
        console.log(`👤 User: Paid USDC on Ethereum, received XRP on XRPL`);
        console.log(`🤖 Resolver: Provided XRP on XRPL, received USDC on Ethereum`);
    }

    async cleanup() {
        console.log('\n🧹 Cleaning up resources...');
        
        if (this.xrplClient) {
            await this.xrplClient.disconnect();
        }
        
        if (this.src?.provider) {
            this.src.provider.destroy();
        }
        
        if (this.src?.node) {
            await this.src.node.stop();
        }
        
        console.log('✅ Cleanup complete');
    }
}

// Main execution function
async function main() {
    const swap = new EVMToXRPLSwap();
    
    try {
        await swap.initialize();
        await swap.executeSwap();
    } catch (error) {
        console.error('❌ Swap failed:', error.message);
        console.error(error.stack);
        process.exit(1);
    } finally {
        await swap.cleanup();
    }
}

// Run the swap
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { EVMToXRPLSwap, config, xrpUtils };
