require('dotenv').config();
const xrpl = require('xrpl');
const { ethers } = require('ethers');
const Sdk = require('@1inch/cross-chain-sdk');
const XRPLEscrowClient = require('../client/XRPLEscrowClient');
const { createServer } = require('prool');
const { anvil } = require('prool/instances');
const { randomBytes } = require('ethers');
const axios = require('axios');
const prompt = require('prompt-sync')();

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
                    address: '0xA0B86991C6218A36C1D19D4a2e9EB0Ce3606EB48',
                    donor: '0x28C6c06298d514Db089934071355E5743bf21d60', // Binance 14 hot wallet (has USDC)
                    decimals: 6,
                    coingeckoId: 'usd-coin'
                },
                USDT: {
                    address: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
                    donor: '0x28C6c06298d514Db089934071355E5743bf21d60', // Binance 14 hot wallet (large USDT holder)
                    decimals: 6,
                    coingeckoId: 'tether'
                },
                DAI: {
                    address: '0x6B175474E89094C44Da98b954EedeAC495271d0F',
                    donor: '0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643', // DSProxy contract with DAI
                    decimals: 18,
                    coingeckoId: 'dai'
                },
                ETH: {
                    address: '0x0000000000000000000000000000000000000000', // Native ETH
                    donor: '0x00000000219ab540356cBB839Cbe05303d7705Fa', // ETH 2.0 deposit contract
                    decimals: 18,
                    coingeckoId: 'ethereum'
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

// Price fetching utility
const priceUtils = {
    async fetchTokenPrices() {
        try {
            console.log('📊 Fetching current token prices from CoinGecko...');
            const tokenIds = Object.values(config.chain.source.tokens)
                .map(token => token.coingeckoId)
                .join(',');
            
            const response = await axios.get(`https://api.coingecko.com/api/v3/simple/price?ids=${tokenIds},ripple&vs_currencies=usd`);
            
            const prices = {
                xrp: response.data.ripple?.usd || 0
            };
            
            // Map prices to token symbols
            Object.entries(config.chain.source.tokens).forEach(([symbol, tokenInfo]) => {
                prices[symbol.toLowerCase()] = response.data[tokenInfo.coingeckoId]?.usd || 0;
            });
            
            console.log('✅ Current prices fetched successfully\n');
            return prices;
        } catch (error) {
            console.warn('⚠️  Failed to fetch prices from CoinGecko, using fallback prices');
            return {
                xrp: 0.50,
                usdc: 1.00,
                usdt: 1.00,
                dai: 1.00,
                eth: 2500.00
            };
        }
    },

    calculateSwapAmount(fromAmount, fromPrice, toPrice) {
        return (fromAmount * fromPrice) / toPrice;
    },

    formatPrice(price) {
        return price < 1 ? price.toFixed(6) : price.toFixed(2);
    }
};

// User interaction utilities
const userInterface = {
    displayTokenOptions(availableTokens) {
        console.log('\n💰 Available tokens for swap:');
        availableTokens.forEach((token, index) => {
            console.log(`  ${index + 1}. ${token}`);
        });
        console.log('');
    },

    selectToken(availableTokens, promptMessage) {
        this.displayTokenOptions(availableTokens);
        
        while (true) {
            const choice = prompt(`${promptMessage} (1-${availableTokens.length}): `);
            const index = parseInt(choice) - 1;
            
            if (index >= 0 && index < availableTokens.length) {
                return availableTokens[index];
            }
            console.log('❌ Invalid choice. Please try again.');
        }
    },

    getSwapAmount(tokenSymbol) {
        while (true) {
            const amount = prompt(`💵 Enter the amount of ${tokenSymbol} you want to swap: `);
            const numAmount = parseFloat(amount);
            
            if (numAmount > 0) {
                return numAmount;
            }
            console.log('❌ Please enter a valid positive number.');
        }
    },

    async displaySwapSummary(fromToken, fromAmount, toToken, toAmount, prices) {
        console.log('\n📋 Swap Summary:');
        console.log('================');
        console.log(`From: ${fromAmount} ${fromToken} ($${priceUtils.formatPrice(fromAmount * prices[fromToken.toLowerCase()])})`);
        console.log(`To: ${toAmount.toFixed(6)} ${toToken} ($${priceUtils.formatPrice(toAmount * prices[toToken.toLowerCase()])})`);
        console.log(`Rate: 1 ${fromToken} = ${(toAmount / fromAmount).toFixed(6)} ${toToken}`);
        console.log('');
        
        const confirm = prompt('✅ Confirm this swap? (y/n): ');
        return confirm.toLowerCase() === 'y' || confirm.toLowerCase() === 'yes';
    }
};

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
        if (token === ethers.ZeroAddress) {
            // For ETH, transfer from donor to this wallet
            const donorWallet = await Wallet.fromAddress(donor, this.provider);
            await donorWallet.transfer(await this.getAddress(), amount);
        } else {
            // For ERC20 tokens
            const donorWallet = await Wallet.fromAddress(donor, this.provider);
            await donorWallet.transferToken(token, await this.getAddress(), amount);
        }
    }

    async getAddress() {
        return this.signer.getAddress();
    }

    async unlimitedApprove(tokenAddress, spender) {
        const currentApprove = await this.getAllowance(tokenAddress, spender);
        if (currentApprove !== 0n) {
            await this.approveToken(tokenAddress, spender, 0n);
        }
        
        // Special handling for USDT - it requires approval to be 0 before setting new approval
        if (tokenAddress.toLowerCase() === '0xdac17f958d2ee523a2206206994597c13d831ec7') {
            // USDT: First approve 0, then approve max
            await this.approveToken(tokenAddress, spender, 0n);
            await this.approveToken(tokenAddress, spender, ethers.parseUnits('1000000', 6)); // 1M USDT
        } else {
            await this.approveToken(tokenAddress, spender, ethers.MaxUint256);
        }
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

        if (logs.length === 0) {
            return [];
        }

        const [data] = logs.map((l) => this.iface.decodeEventLog(event, l.data));
        const immutables = data.at(0);
        const complement = data.at(1);

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
        // User selection state
        this.selectedToken = null;
        this.swapAmount = 0;
        this.prices = {};
        this.xrpAmount = 0;
    }

    async selectTokenAndAmount() {
        console.log('🎯 Welcome to EVM → XRPL Cross-Chain Swap!');
        console.log('=========================================\n');
        
        // Fetch current prices
        this.prices = await priceUtils.fetchTokenPrices();
        
        // Display current prices
        console.log('💹 Current Market Prices:');
        Object.entries(this.prices).forEach(([token, price]) => {
            console.log(`  ${token.toUpperCase()}: $${priceUtils.formatPrice(price)}`);
        });
        console.log('');
        
        // Let user select token
        const availableTokens = Object.keys(config.chain.source.tokens);
        this.selectedToken = userInterface.selectToken(
            availableTokens,
            '🪙 Which token would you like to swap to XRP?'
        );
        
        // Get swap amount
        this.swapAmount = userInterface.getSwapAmount(this.selectedToken);
        
        // Calculate XRP amount
        const tokenPrice = this.prices[this.selectedToken.toLowerCase()];
        const xrpPrice = this.prices.xrp;
        this.xrpAmount = priceUtils.calculateSwapAmount(this.swapAmount, tokenPrice, xrpPrice);
        
        // Show summary and confirm
        const confirmed = await userInterface.displaySwapSummary(
            this.selectedToken,
            this.swapAmount,
            'XRP',
            this.xrpAmount,
            this.prices
        );
        
        if (!confirmed) {
            console.log('❌ Swap cancelled by user');
            process.exit(0);
        }
        
        return {
            token: this.selectedToken,
            amount: this.swapAmount,
            xrpAmount: this.xrpAmount
        };
    }

    async initialize() {
        console.log('\n🚀 Initializing EVM → XRPL Cross-Chain Swap');
        console.log('==========================================\n');

        // Initialize source chain with fork infrastructure
        console.log('🔗 Setting up Ethereum fork...');
        this.src = await initChain(config.chain.source);
        console.log('✅ Ethereum fork initialized');
        
        console.log('');

        // Create wallets for EVM chain
        this.srcChainUser = new Wallet(userPk, this.src.provider);
        this.srcChainResolver = new Wallet(resolverPk, this.src.provider);

        // Initialize escrow factory
        this.srcFactory = new EscrowFactory(this.src.provider, this.src.escrowFactory);

        // Set up selected token for user in source chain
        const tokenInfo = config.chain.source.tokens[this.selectedToken];
        console.log(`💰 Setting up initial ${this.selectedToken} balance for user...`);
        
        if (this.selectedToken === 'ETH') {
            // For ETH, we just need to ensure user has enough ETH
            const ethBalance = await this.src.provider.getBalance(await this.srcChainUser.getAddress());
            const requiredAmount = ethers.parseEther(this.swapAmount.toString());
            if (ethBalance < requiredAmount) {
                // Top up ETH from a donor if needed
                await this.srcChainUser.topUpFromDonor(
                    ethers.ZeroAddress, // ETH
                    tokenInfo.donor,
                    requiredAmount
                );
            }
            // No approval needed for ETH
        } else {
            // For ERC20 tokens
            await this.srcChainUser.topUpFromDonor(
                tokenInfo.address,
                tokenInfo.donor,
                ethers.parseUnits(this.swapAmount.toString(), tokenInfo.decimals)
            );
            await this.srcChainUser.unlimitedApprove(
                tokenInfo.address,
                config.chain.source.limitOrderProtocol
            );
        }

        // Set up resolver contract wallet
        this.srcResolverContract = await Wallet.fromAddress(this.src.resolver, this.src.provider);
        
        console.log(`✅ ${this.selectedToken} balances configured\n`);

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
        let userTokenBalance;
        
        if (this.selectedToken === 'ETH') {
            userTokenBalance = await this.src.provider.getBalance(await this.srcChainUser.getAddress());
            console.log(`💰 User initial ${this.selectedToken} balance: ${ethers.formatEther(userTokenBalance)} ${this.selectedToken}`);
        } else {
            userTokenBalance = await this.srcChainUser.tokenBalance(tokenInfo.address);
            console.log(`💰 User initial ${this.selectedToken} balance: ${ethers.formatUnits(userTokenBalance, tokenInfo.decimals)} ${this.selectedToken}`);
        }
        
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

        // Round XRP amount to avoid decimal precision issues
        const roundedXrpAmount = Math.round(this.xrpAmount * 1000000) / 1000000; // Round to 6 decimal places

        // 1. Create cross-chain order (User wants to trade selected token for XRP)
        const secret = ethers.hexlify(randomBytes(32));
        console.log(`🔐 Generated secret: ${secret}`);

        const srcTimestamp = BigInt((await this.src.provider.getBlock('latest')).timestamp);
        const tokenInfo = config.chain.source.tokens[this.selectedToken];
        
        // Convert amounts to proper units
        const makingAmount = ethers.parseUnits(this.swapAmount.toString(), tokenInfo.decimals);
        const xrpOrderAmount = ethers.parseUnits(roundedXrpAmount.toString(), 6); // Use 6 decimals for representation
        
        console.log(`💱 Swap Details: ${this.swapAmount} ${this.selectedToken} → ${roundedXrpAmount.toFixed(6)} XRP`);
        
        const order = Sdk.CrossChainOrder.new(
            new Sdk.Address(this.src.escrowFactory),
            {
                salt: Sdk.randBigInt(1000n),
                maker: new Sdk.Address(await this.srcChainUser.getAddress()),
                makingAmount: makingAmount, // User offers selected token amount
                takingAmount: xrpOrderAmount, // User wants calculated XRP amount
                makerAsset: new Sdk.Address(tokenInfo.address),
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
                srcSafetyDeposit: ethers.parseUnits('0.1', tokenInfo.decimals),
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
        console.log(`✅ Source escrow deployed, order filled: ${orderFillHash}`);
        console.log(`🔗 EVM Transaction: http://localhost:${this.src.node?.address()?.port || 'unknown'}/tx/${orderFillHash}\n`);

        const srcEscrowEvent = await this.srcFactory.getSrcDeployEvent(srcDeployBlock);
        
        // 3. Create XRPL escrow (where resolver will lock XRP for user)
        console.log('🌊 Creating XRPL escrow...');
        
        // Convert XRP amount to drops (1 XRP = 1,000,000 drops) - use rounded amount
        const xrpInDrops = Math.floor(roundedXrpAmount * 1000000).toString();
        const safetyDepositDrops = '100000'; // 0.1 XRP in drops
        
        const createEscrowPayload = {
            orderHash,
            hashlock: order.escrowExtension.hashLockInfo.toString(),
            maker: this.resolverXRPLWallet.address.toString(), // Resolver provides XRP
            taker: this.userXRPLWallet.address.toString(),     // User receives XRP
            token: "0x0000000000000000000000000000000000000000", // Native XRP
            amount: xrpInDrops, // Calculated XRP amount in drops
            safetyDeposit: safetyDepositDrops, // 0.1 XRP in drops
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
        
        console.log(`✅ Resolver successfully withdrew USDC: ${resolverWithdrawHash}`);

        // 8. Verify final balances
        console.log('🔍 Verifying final balances...');
        const finalUserToken = this.selectedToken === 'ETH' 
            ? await this.src.provider.getBalance(await this.srcChainUser.getAddress())
            : await this.srcChainUser.tokenBalance(tokenInfo.address);
        const finalResolverToken = this.selectedToken === 'ETH'
            ? await this.src.provider.getBalance(this.src.resolver)
            : await this.srcResolverContract.tokenBalance(tokenInfo.address);
        
        const finalUserXRPResponse = await this.xrplClient.request({
            command: "account_info",
            account: this.userXRPLWallet.address
        });
        const finalUserXRP = Number(xrpl.dropsToXrp(finalUserXRPResponse.result.account_data.Balance));

        const tokenDecimals = tokenInfo.decimals;
        console.log(`📊 Final user ${this.selectedToken} balance: ${ethers.formatUnits(finalUserToken, tokenDecimals)} ${this.selectedToken}`);
        console.log(`📊 Final user XRP balance: ${finalUserXRP} XRP`);
        console.log(`📊 Resolver gained ${this.selectedToken}: ${ethers.formatUnits(finalResolverToken, tokenDecimals)} ${this.selectedToken}`);

        console.log('\n🎉 EVM → XRPL Cross-Chain Swap Complete!');
        console.log('=======================================');
        console.log(`📋 Order Hash: ${orderHash}`);
        console.log(`🔐 Secret: ${secret}`);
        console.log(`🌊 XRPL Escrow: ${xrpEscrow.escrowId}`);
        console.log(`💱 Swap: ${this.swapAmount} ${this.selectedToken} → ${this.xrpAmount.toFixed(6)} XRP`);
        console.log(`👤 User: Paid ${this.selectedToken} on Ethereum, received XRP on XRPL`);
        console.log(`🤖 Resolver: Provided XRP on XRPL, received ${this.selectedToken} on Ethereum`);
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
        // Get user input for token selection and amount
        await swap.selectTokenAndAmount();
        
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

module.exports = { EVMToXRPLSwap, config, xrpUtils, priceUtils, userInterface };
