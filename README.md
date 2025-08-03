# Nuvex XRPL Cross-Chain Atomic Swap Platform

**A trustless, atomic swap solution enabling secure cross-chain token exchanges between EVM chains and XRP Ledger**

---

## 🌟 Overview

Nuvex is a sophisticated cross-chain atomic swap platform that facilitates trustless token exchanges between Ethereum Virtual Machine (EVM) compatible blockchains and the XRP Ledger (XRPL). The platform leverages **1inch's battle-tested escrow contracts** on the EVM side and implements a **custom intermediary server** to handle XRPL-specific business logic, ensuring secure and atomic cross-chain transactions.

### Key Features

- ⚡ **True Atomic Swaps**: Either both sides complete successfully or both fail completely
- 🔒 **Hash-Locked Security**: Cryptographic hash locks ensure only authorized parties can withdraw funds
- ⏰ **Time-Locked Safety**: Built-in timelock mechanisms prevent fund lockup and provide escape routes
- 🌐 **Cross-Chain Support**: Seamless swaps between any EVM chain and XRPL
- 🛡️ **Safety Deposits**: Economic incentives prevent malicious behavior
- 🔄 **1inch Integration**: Leverages 1inch Limit Order Protocol for efficient EVM-side execution

---

## 🏗️ Architecture

The Nuvex platform consists of three main components:

### 1. **EVM Smart Contracts** (`/contracts`)
Built on top of 1inch's cross-chain swap infrastructure:
- **EscrowFactory**: Deploys source and destination escrow contracts
- **Resolver**: Manages escrow deployment and fund withdrawal
- **Escrow Contracts**: Hash-locked and time-locked token holders

### 2. **XRPL Intermediary Server** (`/src`)
A Node.js server that manages XRPL-side operations:
- **Escrow Management**: Creates and manages XRPL escrow wallets
- **Transaction Handling**: Processes XRPL payments and withdrawals
- **State Coordination**: Bridges EVM and XRPL transaction states

### 3. **Client SDK** (`/src/client`)
JavaScript client library for easy integration:
- **XRPLEscrowClient**: High-level API for interacting with the platform
- **Utilities**: Helper functions for wallet management and transaction handling

---

---

## 🛡️ Security Features

### Hash Locks
- **Keccak256 Hashing**: Uses Ethereum-compatible hashing for cross-chain consistency
- **Secret Management**: 32-byte cryptographically secure random secrets
- **Atomic Revelation**: Secret reveals unlock funds on both chains simultaneously

### Time Locks
The platform implements sophisticated timelock mechanisms with different phases:

| Phase | Window | Purpose |
|-------|--------|---------|
| **Private Withdrawal** | 10-120s | Only designated party can withdraw |
| **Public Withdrawal** | 120s-100s | Anyone can withdraw with valid secret |
| **Cancellation** | 121s+ | Refund original depositors |
| **Rescue** | Custom delay | Emergency fund recovery |

### Safety Deposits
- **Economic Security**: Prevents rational attacks through economic incentives
- **Configurable Amounts**: Flexible safety deposit requirements
- **Automatic Refunds**: Safety deposits returned upon successful completion

---

## 📁 Project Structure

```
nuvexMain/
├── contracts/                    # Smart contracts for EVM chains
│   ├── src/
│   │   ├── Resolver.sol          # Main resolver contract
│   │   └── TestEscrowFactory.sol # Factory for test deployments
│   ├── lib/cross-chain-swap/     # 1inch cross-chain swap library
│   └── script/                   # Deployment scripts
├── src/                          # XRPL server implementation
│   ├── client/                   # Client SDK
│   │   ├── XRPLEscrowClient.js   # Main client interface
│   │   └── XRPLEscrowUtils.js    # Utility functions
│   ├── controllers/              # API controllers
│   │   ├── createDstController.js
│   │   ├── fundController.js
│   │   ├── withdrawController.js
│   │   ├── cancelController.js
│   │   └── rescueController.js
│   ├── services/
│   │   └── escrowService.js      # Core escrow business logic
│   ├── utils/                    # Utility modules
│   │   ├── hash.js               # Cryptographic functions
│   │   ├── timelock.js           # Timelock management
│   │   └── faucet.js             # XRPL testnet faucet
│   ├── examples/                 # Example implementations
│   │   ├── evm->xrp.js           # EVM to XRPL swap example
│   │   └── xrp->evm.js           # XRPL to EVM swap example
│   ├── XRPLEscrow.js             # Main server class
│   ├── config.js                 # Configuration management
│   └── index.js                  # Server entry point
└── package.json                  # Dependencies and scripts
```

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** v16+ and npm
- **Foundry** for smart contract development
- **Access to EVM RPC** (Ethereum, Polygon, BSC, etc.)
- **XRPL Network Access** (Mainnet or Testnet)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/nuvex-xrpl.git
   cd nuvex-xrpl
   ```

2. **Install dependencies**
   ```bash
   npm install && forge install && forge build
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Deploy smart contracts** (if needed)
   ```bash
   cd contracts
   forge script script/DeployResolver.s.sol --broadcast
   ```

5. **Start the XRPL server**
   ```bash
   npm start
   ```

### Environment Variables

```bash
# XRPL Configuration
XRPL_NETWORK=wss://s.altnet.rippletest.net:51233  # Testnet
# XRPL_NETWORK=wss://xrplcluster.com              # Mainnet

# Server Configuration
PORT=3000
RESCUE_DELAY=86400  # 24 hours in seconds

# EVM Configuration (for examples)
SRC_CHAIN_RPC=https://eth.merkle.io
DST_CHAIN_RPC=https://bsc-rpc.publicnode.com
```

---

## 💻 Usage Examples

### Basic EVM → XRPL Swap

```javascript
const { XRPLEscrowClient } = require('./src/client/XRPLEscrowClient');

async function evmToXrplSwap() {
    const client = new XRPLEscrowClient({ baseUrl: 'http://localhost:3000' });
    
    // 1. Create XRPL escrow
    const escrow = await client.createDestinationEscrow({
        orderHash: '0x...', // From EVM escrow creation
        hashlock: '0x...', // Hash of secret
        maker: 'rResolver...', // Resolver XRPL address
        taker: 'rUser...', // User XRPL address
        token: '0x0000000000000000000000000000000000000000', // XRP
        amount: '5000000', // 5 XRP in drops
        safetyDeposit: '100000', // 0.1 XRP
        timelocks: '...',
        type: 'dst'
    });
    
    // 2. Fund the escrow
    await client.fundEscrow(escrow.escrowId, {
        fromAddress: 'rResolver...',
        txHash: '0x...' // XRPL transaction hash
    });
    
    // 3. User withdraws (reveals secret)
    const result = await client.withdraw(
        escrow.escrowId, 
        '0x...', // 32-byte secret
        'rUser...', // User address
        false // Private withdrawal
    );
    
    console.log('Swap completed!', result);
}
```

### Using the Client SDK

```javascript
const { XRPLEscrowClient } = require('./src/client/XRPLEscrowClient');

// Initialize client
const client = new XRPLEscrowClient({
    baseUrl: 'http://localhost:3000',
    timeout: 30000,
    retries: 3
});

// Generate secret and hash
const secret = XRPLEscrowClient.generateSecret();
const hashlock = XRPLEscrowClient.hashSecret(secret);

// Wait for specific escrow status
await client.waitForStatus(escrowId, 'funded', 60000);

// Check server health
const health = await client.getHealth();
```

---

## 🧪 Running Examples

The project includes complete working examples for both swap directions:

### EVM → XRPL Swap Example
```bash
npm run evm2xrp
```
Demonstrates a user trading USDC on Ethereum for XRP on XRPL.

### XRPL → EVM Swap Example  
```bash
npm run xrp2evm
```
Demonstrates a user trading XRP on XRPL for USDC on BSC.

Both examples use:
- **Fork Infrastructure**: Real blockchain state with local testing
- **Live XRPL Testnet**: Actual XRPL transactions
- **Complete Workflows**: Full end-to-end swap processes

---

## 📡 API Reference

### Server Endpoints

#### `POST /escrow/create-dst`
Create a destination escrow on XRPL.

**Request Body:**
```json
{
    "orderHash": "0x...",
    "hashlock": "0x...", 
    "maker": "rMaker...",
    "taker": "rTaker...",
    "token": "0x0000000000000000000000000000000000000000",
    "amount": "1000000",
    "safetyDeposit": "100000",
    "timelocks": "123456789",
    "type": "dst"
}
```

#### `POST /escrow/{escrowId}/fund`
Fund an existing escrow.

**Request Body:**
```json
{
    "fromAddress": "rFunder...",
    "txHash": "ABC123..."
}
```

#### `POST /escrow/{escrowId}/withdraw`
Withdraw funds from escrow using secret.

**Request Body:**
```json
{
    "secret": "0x...",
    "callerAddress": "rCaller...",
    "isPublic": false
}
```

#### `POST /escrow/{escrowId}/cancel`
Cancel an escrow and refund participants.

#### `POST /escrow/{escrowId}/rescue`
Emergency fund recovery (after rescue delay).

#### `GET /escrow/{escrowId}`
Get escrow details and status.

#### `GET /health`
Server health check.

---

## 🔧 Development

### Running Tests

```bash
# Smart contract tests
cd contracts
forge test

```

### Building Contracts

```bash
cd contracts
forge build
```

### Code Structure

The codebase follows a modular architecture:

- **Controllers**: Handle HTTP requests and responses
- **Services**: Implement core business logic
- **Utils**: Provide reusable utility functions
- **Client**: SDK for external integration
- **Examples**: Real-world usage demonstrations

---

## 🛠️ Smart Contract Integration

### Deploying Your Own Resolver

```solidity
// Deploy with your factory and limit order protocol addresses
Resolver resolver = new Resolver(
    IEscrowFactory(0x...),    // Your escrow factory
    IOrderMixin(0x...),       // 1inch Limit Order Protocol
    owner                     // Your address
);
```

### Creating Cross-Chain Orders

```javascript
const Sdk = require('@1inch/cross-chain-sdk');

const order = Sdk.CrossChainOrder.new(
    new Sdk.Address(escrowFactory),
    {
        salt: Sdk.randBigInt(1000n),
        maker: userAddress,
        makingAmount: ethers.parseUnits('10', 6), // 10 USDC
        takingAmount: ethers.parseUnits('5', 6),  // 5 XRP worth
        makerAsset: usdcAddress,
        takerAsset: targetTokenAddress
    },
    {
        hashLock: Sdk.HashLock.forSingleFill(secret),
        timeLocks: Sdk.TimeLocks.new({
            srcWithdrawal: 10n,
            srcPublicWithdrawal: 120n,
            srcCancellation: 121n,
            // ... other timelock values
        }),
        srcChainId: 1, // Ethereum
        dstChainId: 56 // BSC
    }
);
```

---

## 🌐 Supported Networks

### EVM Chains
- **Ethereum Mainnet**
- **Polygon**
- **Binance Smart Chain**
- **Arbitrum**
- **Optimism** 
- **Avalanche**
- **Any EVM-compatible chain**

### XRPL Networks
- **XRPL Mainnet**
- **XRPL Testnet** (for development)

---

## ⚠️ Security Considerations

### For Developers
- **Timelock Validation**: Always validate timelock windows before operations
- **Secret Management**: Generate cryptographically secure secrets
- **Fund Safety**: Implement proper error handling for fund recovery

### For Users
- **Test First**: Use testnet for initial integrations
- **Monitor Timelocks**: Be aware of withdrawal and cancellation windows
- **Backup Secrets**: Securely store secrets for fund recovery

### For Resolvers
- **Economic Security**: Ensure adequate safety deposits
- **Monitoring**: Implement automated monitoring for escrow states
- **Contingency Plans**: Have procedures for rescue operations

---

### Code Standards
- **JavaScript**: ESLint with standard configuration
- **Solidity**: Follow 1inch style guidelines
- **Documentation**: Update README for API changes


**Built with ❤️ for the cross-chain future**
