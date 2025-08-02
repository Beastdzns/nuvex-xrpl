require('dotenv/config');
const xrpl = require('xrpl');
const { ethers } = require('ethers');
const Sdk = require('@1inch/cross-chain-sdk');
const { XRPLEscrowClient } = require('./nuvex-xrpl-server/client.js');
const { createServer } = require('prool');
const { anvil } = require('prool/instances');
const { randomBytes } = require('ethers');

// Import contract artifacts
const factoryContract = require('../../dist/contracts/TestEscrowFactory.sol/TestEscrowFactory.json');
const resolverContract = require('../../dist/contracts/Resolver.sol/Resolver.json');

// Configuration based on test setup with environment variables
const config = {
    chain: {
        source: {
            chainId: Sdk.NetworkEnum.ETHEREUM,
            url: process.env.SRC_CHAIN_RPC || 'https://eth.merkle.io',
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
        },
        destination: {
            chainId: Sdk.NetworkEnum.BINANCE,
            url: process.env.DST_CHAIN_RPC || 'wss://bsc-rpc.publicnode.com',
            createFork: process.env.DST_CHAIN_CREATE_FORK !== 'false',
            limitOrderProtocol: '0x111111125421ca6dc452d289314280a0f8842a65',
            wrappedNative: '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c',
            ownerPrivateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
            tokens: {
                USDC: {
                    address: '0x8965349fb649a33a30cbfda057d8ec2c48abe2a2',
                    donor: '0x4188663a85C92EEa35b5AD3AA5cA7CeB237C6fe9'
                }
            }
        }
    }
};

// Test private keys (same as in test infrastructure)
const userPk = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const resolverPk = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a';

// XRPL utility functions (keeping from working version)
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
                xrplClient = new xrpl.Client('wss://s.altnet.rippletest.net:51233');
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
                console.log(`Wallet ${wallet.address} current balance: ${currentBalance} XRP`);
                
                if (currentBalance >= minBalance) {
                    console.log(`Wallet ${wallet.address} has sufficient balance, skipping funding`);
                    return;
                }
            } catch (error) {
                console.log(`Wallet ${wallet.address} account not found, proceeding with funding`);
            }

            console.log(`Funding wallet ${wallet.address} from testnet faucet...`);
            await xrplClient.fundWallet(wallet);
            console.log(`Successfully funded wallet ${wallet.address}`);
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
                xrplClient = new xrpl.Client('wss://s.altnet.rippletest.net:51233');
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

            console.log(`Sending ${amountStr} XRP drops from ${fromWallet.address} to ${toAddress}...`);

            const response = await xrplClient.submitAndWait(payment, { wallet: fromWallet });
            
            if (response.result.validated && response.result.meta && 
                typeof response.result.meta === 'object' && 'TransactionResult' in response.result.meta) {
                if (response.result.meta.TransactionResult === 'tesSUCCESS') {
                    console.log(`Successfully sent ${amountStr} XRP drops. Transaction hash: ${response.result.hash}`);
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

// Real EVM Wallet implementation (based on test infrastructure)
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
        await this.approveToken(tokenAddress, spender, (1n << 256n) - 1n);
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

// Real Resolver implementation (based on test infrastructure)
class Resolver {
    constructor(srcAddress, dstAddress) {
        this.srcAddress = srcAddress;
        this.dstAddress = dstAddress;
        this.iface = new ethers.Interface(resolverContract.abi);
    }

    deployDst(immutables) {
        return {
            to: this.dstAddress,
            data: this.iface.encodeFunctionData('deployDst', [
                immutables.build(),
                immutables.timeLocks.toSrcTimeLocks().privateCancellation
            ]),
            value: immutables.safetyDeposit
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

// Real EscrowFactory implementation (based on test infrastructure)
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

    async getDestinationImpl() {
        return Sdk.Address.fromBigInt(
            BigInt(await this.provider.call({
                to: this.address,
                data: ethers.id('ESCROW_DST_IMPLEMENTATION()').slice(0, 10)
            }))
        );
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
 * Real XRPL → EVM Cross-Chain Atomic Swap Implementation
 * 
 * This implementation uses real blockchain interactions with fork infrastructure
 * similar to the test setup. It demonstrates:
 * 1. Real contract deployments on forked chains
 * 2. Real XRPL transactions on testnet
 * 3. Proper token transfers and approvals
 * 4. Hash-locked atomic swaps
 */
class XRPLToEVMSwap {
    constructor() {
        this.xrplClient = null;
        this.nuvexClient = null;
        this.src = null;
        this.dst = null;
        this.srcChainUser = null;
        this.dstChainUser = null;
        this.srcChainResolver = null;
        this.dstChainResolver = null;
        this.srcFactory = null;
        this.dstFactory = null;
        this.srcResolverContract = null;
        this.dstResolverContract = null;
        this.resolver = null;
        this.makerXRPLWallet = null;
        this.takerXRPLWallet = null;
    }

    async initialize() {
        console.log('🚀 Initializing Real XRPL → EVM Cross-Chain Swap');
        console.log('==============================================\n');

        // Initialize chains with fork infrastructure
        console.log('🔗 Setting up blockchain forks...');
        this.src = await initChain(config.chain.source);
        this.dst = await initChain(config.chain.destination);
        console.log('✅ Blockchain forks initialized\n');

        // Create wallets for both chains
        this.srcChainUser = new Wallet(userPk, this.src.provider);
        this.dstChainUser = new Wallet(userPk, this.dst.provider);
        this.srcChainResolver = new Wallet(resolverPk, this.src.provider);
        this.dstChainResolver = new Wallet(resolverPk, this.dst.provider);

        // Initialize escrow factories
        this.srcFactory = new EscrowFactory(this.src.provider, this.src.escrowFactory);
        this.dstFactory = new EscrowFactory(this.dst.provider, this.dst.escrowFactory);

        // Set up USDC for user in SRC chain (this is where user has tokens to start)
        console.log('💰 Setting up initial token balances...');
        await this.srcChainUser.topUpFromDonor(
            config.chain.source.tokens.USDC.address,
            config.chain.source.tokens.USDC.donor,
            ethers.parseUnits('1000', 6)
        );
        await this.srcChainUser.unlimitedApprove(
            config.chain.source.tokens.USDC.address,
            config.chain.source.limitOrderProtocol
        );

        // Set up USDC for resolver in DST chain (this is where resolver will provide tokens)
        this.srcResolverContract = await Wallet.fromAddress(this.src.resolver, this.src.provider);
        this.dstResolverContract = await Wallet.fromAddress(this.dst.resolver, this.dst.provider);
        
        await this.dstResolverContract.topUpFromDonor(
            config.chain.destination.tokens.USDC.address,
            config.chain.destination.tokens.USDC.donor,
            ethers.parseUnits('2000', 6)
        );
        
        // Top up contract for gas
        await this.dstChainResolver.transfer(this.dst.resolver, ethers.parseEther('1'));
        await this.dstResolverContract.unlimitedApprove(
            config.chain.destination.tokens.USDC.address, 
            this.dst.escrowFactory
        );
        
        console.log('✅ Token balances configured\n');

        // Initialize resolver
        this.resolver = new Resolver(this.src.resolver, this.dst.resolver);

        // Initialize XRPL
        console.log('🌊 Connecting to XRPL testnet...');
        this.xrplClient = new xrpl.Client('wss://s.altnet.rippletest.net:51233');
        await this.xrplClient.connect();

        this.makerXRPLWallet = xrpUtils.createXRPLWalletFromEthKey(userPk);
        this.takerXRPLWallet = xrpUtils.createXRPLWalletFromEthKey(resolverPk);

        await xrpUtils.refuelWalletFromFaucet(this.makerXRPLWallet, this.xrplClient);
        await xrpUtils.refuelWalletFromFaucet(this.takerXRPLWallet, this.xrplClient);
        console.log('✅ XRPL wallets funded\n');

        // Initialize Nuvex client
        this.nuvexClient = new XRPLEscrowClient({ baseUrl: 'http://localhost:3000' });
        console.log('✅ Nuvex client initialized\n');

        console.log(`📝 Maker XRPL: ${this.makerXRPLWallet.address}`);
        console.log(`📝 Taker XRPL: ${this.takerXRPLWallet.address}`);
        console.log(`📝 Maker EVM: ${await this.srcChainUser.getAddress()}`);
        console.log(`📝 Taker EVM: ${await this.dstChainResolver.getAddress()}\n`);
    }

    async executeSwap() {
        console.log('🔄 Starting XRPL → EVM Atomic Swap');
        console.log('=================================\n');

        // 1. Create cross-chain order
        const secret = ethers.hexlify(randomBytes(32));
        console.log(`🔐 Generated secret: ${secret}`);

        const srcTimestamp = BigInt((await this.src.provider.getBlock('latest')).timestamp);
        
        const order = Sdk.CrossChainOrder.new(
            new Sdk.Address(this.src.escrowFactory), // Source factory (where user creates order)
            {
                salt: Sdk.randBigInt(1000n),
                maker: new Sdk.Address(await this.srcChainUser.getAddress()),
                makingAmount: ethers.parseUnits('1', 6), // User offers 1 USDC from source chain
                takingAmount: ethers.parseUnits('1', 6), // User wants 1 USDC on destination chain
                takerAsset: new Sdk.Address(config.chain.destination.tokens.USDC.address),
                makerAsset: new Sdk.Address(config.chain.source.tokens.USDC.address)
            },
            {
                hashLock: Sdk.HashLock.forSingleFill(secret),
                timeLocks: Sdk.TimeLocks.new({
                    srcWithdrawal: 10n,
                    srcPublicWithdrawal: 120n,
                    srcCancellation: 121n,
                    srcPublicCancellation: 122n,
                    dstWithdrawal: 10n,
                    dstPublicWithdrawal: 100n,
                    dstCancellation: 101n
                }),
                srcChainId: config.chain.source.chainId,
                dstChainId: config.chain.destination.chainId,
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

        const orderHash = order.getOrderHash(config.chain.source.chainId);
        console.log(`📋 Order created: ${orderHash}\n`);

        // 2. Deploy destination escrow (where user will receive tokens)
        console.log('🏗️  Deploying destination escrow...');
        const deployedAtTimelocks = order.escrowExtension.timeLocks;
        deployedAtTimelocks.setDeployedAt(srcTimestamp);
        
        const dstImmutables = Sdk.Immutables.new({
            orderHash: orderHash,
            hashLock: order.escrowExtension.hashLockInfo,
            maker: new Sdk.Address(await this.srcChainUser.getAddress()),
            taker: new Sdk.Address(this.resolver.dstAddress),
            token: new Sdk.Address(config.chain.destination.tokens.USDC.address),
            amount: order.takingAmount,
            safetyDeposit: order.escrowExtension.dstSafetyDeposit,
            timeLocks: deployedAtTimelocks
        });

        const {txHash: dstDepositHash, blockTimestamp: dstDeployedAt} = 
            await this.dstChainResolver.send(this.resolver.deployDst(dstImmutables));
        
        console.log(`✅ Destination escrow deployed: ${dstDepositHash}\n`);

        // 3. Create XRPL escrow (where user will lock XRP)
        console.log('🌊 Creating XRPL escrow...');
        
        // Pack timelocks for Nuvex server
        function packTimelocks(timelocks) {
            // Extract BigInt values and convert to regular numbers for packing
            const offsets = [
                Number(timelocks._srcWithdrawal || 10n),
                Number(timelocks._srcPublicWithdrawal || 120n), 
                Number(timelocks._srcCancellation || 121n),
                Number(timelocks._srcPublicCancellation || 122n),
                Number(timelocks._dstWithdrawal || 10n),
                Number(timelocks._dstPublicWithdrawal || 100n),
                Number(timelocks._dstCancellation || 101n)
            ];
            
            let packed = 0n;
            for (let i = 0; i < 7; i++) {
                packed |= BigInt(offsets[i]) << BigInt(i * 32);
            }
            return packed;
        }

        const createEscrowPayload = {
            orderHash,
            hashlock: order.escrowExtension.hashLockInfo.toString(),
            maker: this.makerXRPLWallet.address.toString(),
            taker: this.takerXRPLWallet.address.toString(),
            token: "0x0000000000000000000000000000000000000000", // Native XRP
            amount: '1000000', // 1 XRP in drops
            safetyDeposit: '100000', // 0.1 XRP in drops
            timelocks: packTimelocks(order.escrowExtension.timeLocks).toString()
        };

        const xrpEscrow = await this.nuvexClient.createDestinationEscrow(createEscrowPayload);
        console.log(`✅ XRPL escrow created: ${xrpEscrow.escrowId}\n`);

        // 4. Fund XRPL escrow
        console.log('💰 Funding XRPL escrow...');
        const makerDepositHash = await xrpUtils.sendXRP(
            this.makerXRPLWallet, 
            xrpEscrow.walletAddress, 
            createEscrowPayload.amount,
            this.xrplClient
        );
        
        const takerDepositHash = await xrpUtils.sendXRP(
            this.takerXRPLWallet,
            xrpEscrow.walletAddress,
            createEscrowPayload.safetyDeposit,
            this.xrplClient
        );

        const fundedEscrow = await this.nuvexClient.fundEscrow(xrpEscrow.escrowId, {
            fromAddress: this.makerXRPLWallet.address,
            txHash: [makerDepositHash, takerDepositHash].join(',')
        });
        
        console.log(`✅ XRPL escrow funded`);
        console.log(`🔗 Maker deposit: https://testnet.xrpl.org/transactions/${makerDepositHash}`);
        console.log(`🔗 Taker deposit: https://testnet.xrpl.org/transactions/${takerDepositHash}\n`);

        // 5. Wait for timelock and then withdraw
        console.log('⏳ Waiting for withdrawal timelock...');
        await new Promise(resolve => setTimeout(resolve, 11000)); // Wait 11 seconds
        
        // 6. Resolver withdraws from destination chain revealing secret
        console.log('🎯 Resolver withdrawing from destination...');
        const ESCROW_DST_IMPLEMENTATION = await this.dstFactory.getDestinationImpl();
        const dstComplement = Sdk.DstImmutablesComplement.new({
            maker: new Sdk.Address(await this.srcChainUser.getAddress()),
            amount: order.takingAmount,
            token: new Sdk.Address(config.chain.destination.tokens.USDC.address),
            safetyDeposit: order.escrowExtension.dstSafetyDeposit,
        });

        const dstEscrowAddress = new Sdk.EscrowFactory(new Sdk.Address(this.dst.escrowFactory))
            .getDstEscrowAddress(
                dstImmutables,
                dstComplement,
                dstDeployedAt,
                new Sdk.Address(this.resolver.dstAddress),
                ESCROW_DST_IMPLEMENTATION
            );

        await this.dstChainResolver.send(
            this.resolver.withdraw('dst', dstEscrowAddress, secret, dstImmutables.withDeployedAt(dstDeployedAt))
        );
        console.log('✅ Destination withdrawal complete\n');

        // 7. Withdraw from XRPL using the same secret
        console.log('🌊 Withdrawing from XRPL escrow...');
        const xrplWithdrawal = await this.nuvexClient.withdraw(
            xrpEscrow.escrowId, 
            secret, 
            this.takerXRPLWallet.address, 
            false
        );
        
        console.log(`✅ XRPL withdrawal complete`);
        console.log(`🔗 Withdrawal TX: https://testnet.xrpl.org/transactions/${xrplWithdrawal.txHash}\n`);

        console.log('🎉 XRPL → EVM Cross-Chain Swap Complete!');
        console.log('=====================================');
        console.log(`📋 Order: ${orderHash}`);
        console.log(`🔐 Secret: ${secret}`);
        console.log(`🌊 XRPL Escrow: ${xrpEscrow.escrowId}`);
        console.log(`💰 Amount Swapped: 1 XRP ↔ 1 USDC`);
    }

    async cleanup() {
        console.log('\n🧹 Cleaning up resources...');
        
        if (this.xrplClient) {
            await this.xrplClient.disconnect();
        }
        
        if (this.src?.provider) {
            this.src.provider.destroy();
        }
        
        if (this.dst?.provider) {
            this.dst.provider.destroy();
        }
        
        if (this.src?.node) {
            await this.src.node.stop();
        }
        
        if (this.dst?.node) {
            await this.dst.node.stop();
        }
        
        console.log('✅ Cleanup complete');
    }
}

// Main execution function
async function main() {
    const swap = new XRPLToEVMSwap();
    
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

// Run the example
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { XRPLToEVMSwap, config, xrpUtils };
