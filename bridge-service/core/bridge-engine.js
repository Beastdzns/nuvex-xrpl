import xrpl from 'xrpl';
import crypto from 'crypto';
import { z } from 'zod';
import { keccak256 } from 'ethers';
import { Logger } from '../utils/logger.js';
import { SecurityManager } from '../utils/security.js';

// Validation schemas
const CreateEscrowSchema = z.object({
  orderHash: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
  hashlock: z.string(),
  maker: z.string().regex(/^r[a-zA-Z0-9]{24,34}$/),
  taker: z.string().regex(/^r[a-zA-Z0-9]{24,34}$/),
  token: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  amount: z.string(),
  safetyDeposit: z.string(),
  timelocks: z.string(),
  type: z.enum(['src', 'dst'])
});

const FundEscrowSchema = z.object({
  fromAddress: z.string(),
  txHash: z.string().regex(/^[A-F0-9]{64}$/i)
});

/**
 * Nuvex Bridge Core Engine
 * Handles XRPL atomic swap operations with enhanced security
 */
export class NuvexBridgeCore {
  constructor(config = {}) {
    this.client = null;
    this.logger = new Logger('BridgeCore');
    this.security = new SecurityManager();
    
    this.config = {
      network: config.network || 'wss://s.altnet.rippletest.net:51233',
      rescueDelay: config.rescueDelay || 604800, // 7 days
      maxEscrowValue: config.maxEscrowValue || '1000000', // 1M XRP
      minConfirmations: config.minConfirmations || 1,
      ...config
    };
    
    // Secure storage for active bridge operations
    this.bridgeOperations = new Map();
    this.walletSeeds = new Map();
    
    this.logger.info('Nuvex Bridge Core initialized', { 
      network: this.config.network,
      rescueDelay: this.config.rescueDelay 
    });
  }

  async initialize() {
    try {
      this.client = new xrpl.Client(this.config.network);
      await this.client.connect();
      this.logger.info(`Connected to XRPL network: ${this.config.network}`);
      return true;
    } catch (error) {
      this.logger.error('Failed to connect to XRPL', { error: error.message });
      return false;
    }
  }

  /**
   * Generate a secure wallet for bridge operations
   */
  async generateBridgeWallet() {
    const entropy = crypto.randomBytes(32);
    const wallet = xrpl.Wallet.fromEntropy(entropy);
    
    // Store seed securely (in production, use proper key management)
    this.walletSeeds.set(wallet.address, wallet.seed);
    
    this.logger.info('Generated new bridge wallet', { 
      address: wallet.address 
    });
    
    return {
      address: wallet.address,
      classicAddress: wallet.classicAddress
    };
  }

  /**
   * Create a destination escrow for cross-chain operations
   */
  async createDestinationEscrow(params) {
    try {
      // Validate input parameters
      const validatedParams = CreateEscrowSchema.parse(params);
      
      // Security checks
      this.security.validateEscrowParams(validatedParams);
      
      const { orderHash, hashlock, maker, taker, amount, safetyDeposit, timelocks } = validatedParams;
      
      // Generate unique escrow wallet
      const escrowWallet = await this.generateBridgeWallet();
      const escrowId = this.generateEscrowId(orderHash);
      
      // Calculate required deposits
      const bridgeAmount = BigInt(amount);
      const depositAmount = BigInt(safetyDeposit);
      const totalRequired = bridgeAmount + depositAmount;
      
      // Store escrow metadata
      const escrowData = {
        id: escrowId,
        orderHash,
        hashlock,
        maker,
        taker,
        amount: bridgeAmount.toString(),
        safetyDeposit: depositAmount.toString(),
        totalRequired: totalRequired.toString(),
        timelocks: JSON.parse(timelocks),
        wallet: escrowWallet,
        status: 'created',
        createdAt: new Date().toISOString(),
        type: 'destination'
      };
      
      this.bridgeOperations.set(escrowId, escrowData);
      
      this.logger.info('Created destination escrow', { 
        escrowId, 
        orderHash, 
        maker, 
        taker,
        amount: bridgeAmount.toString()
      });
      
      return {
        escrowId,
        walletAddress: escrowWallet.address,
        requiredDeposit: {
          xrp: xrpl.dropsToXrp(totalRequired.toString()),
          drops: totalRequired.toString()
        },
        hashlock,
        timelocks: escrowData.timelocks,
        status: 'awaiting_funding'
      };
      
    } catch (error) {
      this.logger.error('Failed to create destination escrow', { 
        error: error.message,
        params 
      });
      throw new Error(`Escrow creation failed: ${error.message}`);
    }
  }

  /**
   * Fund an existing escrow
   */
  async fundEscrow(escrowId, fundingData) {
    try {
      const validatedData = FundEscrowSchema.parse(fundingData);
      const escrow = this.bridgeOperations.get(escrowId);
      
      if (!escrow) {
        throw new Error('Escrow not found');
      }
      
      if (escrow.status !== 'created') {
        throw new Error(`Invalid escrow status: ${escrow.status}`);
      }
      
      // Verify the funding transaction
      const txResult = await this.client.request({
        command: 'tx',
        transaction: validatedData.txHash
      });
      
      if (!txResult.result || txResult.result.validated !== true) {
        throw new Error('Transaction not validated');
      }
      
      const tx = txResult.result;
      
      // Validate transaction details
      if (tx.Destination !== escrow.wallet.address) {
        throw new Error('Transaction destination mismatch');
      }
      
      if (tx.Account !== validatedData.fromAddress) {
        throw new Error('Transaction sender mismatch');
      }
      
      const receivedAmount = BigInt(tx.Amount);
      const requiredAmount = BigInt(escrow.totalRequired);
      
      if (receivedAmount < requiredAmount) {
        throw new Error(`Insufficient funding: received ${receivedAmount}, required ${requiredAmount}`);
      }
      
      // Update escrow status
      escrow.status = 'funded';
      escrow.fundingTx = validatedData.txHash;
      escrow.fundedAt = new Date().toISOString();
      escrow.actualAmount = receivedAmount.toString();
      
      this.bridgeOperations.set(escrowId, escrow);
      
      this.logger.info('Escrow funded successfully', { 
        escrowId, 
        txHash: validatedData.txHash,
        amount: receivedAmount.toString()
      });
      
      return {
        success: true,
        escrowId,
        status: 'funded',
        txHash: validatedData.txHash,
        confirmedAmount: xrpl.dropsToXrp(receivedAmount.toString())
      };
      
    } catch (error) {
      this.logger.error('Failed to fund escrow', { 
        escrowId, 
        error: error.message 
      });
      throw new Error(`Escrow funding failed: ${error.message}`);
    }
  }

  /**
   * Withdraw funds from escrow using secret
   */
  async withdraw(escrowId, secret, recipientAddress, isPublic = false) {
    try {
      const escrow = this.bridgeOperations.get(escrowId);
      
      if (!escrow) {
        throw new Error('Escrow not found');
      }
      
      if (escrow.status !== 'funded') {
        throw new Error(`Cannot withdraw from escrow with status: ${escrow.status}`);
      }
      
      // Validate secret against hashlock
      const secretHash = keccak256(secret);
      if (secretHash !== escrow.hashlock) {
        throw new Error('Invalid secret provided');
      }
      
      // Check timelock constraints
      const now = Math.floor(Date.now() / 1000);
      const timelocks = escrow.timelocks;
      
      if (!isPublic && now < timelocks.dstWithdrawal) {
        throw new Error('Withdrawal timelock not yet expired');
      }
      
      if (isPublic && now < timelocks.dstPublicWithdrawal) {
        throw new Error('Public withdrawal timelock not yet expired');
      }
      
      // Get escrow wallet
      const walletSeed = this.walletSeeds.get(escrow.wallet.address);
      if (!walletSeed) {
        throw new Error('Escrow wallet seed not found');
      }
      
      const wallet = xrpl.Wallet.fromSeed(walletSeed);
      
      // Calculate withdrawal amount (subtract network fees)
      const totalBalance = BigInt(escrow.actualAmount);
      const networkFee = BigInt(12); // 12 drops for standard transaction
      const withdrawAmount = totalBalance - networkFee;
      
      // Create payment transaction
      const payment = {
        TransactionType: 'Payment',
        Account: wallet.address,
        Destination: recipientAddress,
        Amount: withdrawAmount.toString(),
        Fee: networkFee.toString()
      };
      
      // Submit and wait for validation
      const response = await this.client.submitAndWait(payment, {
        wallet,
        autofill: true
      });
      
      if (response.result.meta.TransactionResult !== 'tesSUCCESS') {
        throw new Error(`Transaction failed: ${response.result.meta.TransactionResult}`);
      }
      
      // Update escrow status
      escrow.status = 'withdrawn';
      escrow.withdrawalTx = response.result.hash;
      escrow.withdrawnAt = new Date().toISOString();
      escrow.recipientAddress = recipientAddress;
      escrow.secret = secret;
      
      this.bridgeOperations.set(escrowId, escrow);
      
      this.logger.info('Escrow withdrawal successful', { 
        escrowId, 
        txHash: response.result.hash,
        recipient: recipientAddress,
        amount: xrpl.dropsToXrp(withdrawAmount.toString())
      });
      
      return {
        success: true,
        txHash: response.result.hash,
        amount: xrpl.dropsToXrp(withdrawAmount.toString()),
        recipient: recipientAddress
      };
      
    } catch (error) {
      this.logger.error('Withdrawal failed', { 
        escrowId, 
        error: error.message 
      });
      throw new Error(`Withdrawal failed: ${error.message}`);
    }
  }

  /**
   * Cancel escrow and return funds to taker
   */
  async cancel(escrowId, recipientAddress) {
    try {
      const escrow = this.bridgeOperations.get(escrowId);
      
      if (!escrow) {
        throw new Error('Escrow not found');
      }
      
      if (escrow.status !== 'funded') {
        throw new Error(`Cannot cancel escrow with status: ${escrow.status}`);
      }
      
      // Check if cancellation timelock has expired
      const now = Math.floor(Date.now() / 1000);
      const timelocks = escrow.timelocks;
      
      if (now < timelocks.dstCancellation) {
        throw new Error('Cancellation timelock not yet expired');
      }
      
      // Get escrow wallet
      const walletSeed = this.walletSeeds.get(escrow.wallet.address);
      if (!walletSeed) {
        throw new Error('Escrow wallet seed not found');
      }
      
      const wallet = xrpl.Wallet.fromSeed(walletSeed);
      
      // Calculate refund amount
      const totalBalance = BigInt(escrow.actualAmount);
      const networkFee = BigInt(12);
      const refundAmount = totalBalance - networkFee;
      
      // Create refund transaction
      const payment = {
        TransactionType: 'Payment',
        Account: wallet.address,
        Destination: recipientAddress,
        Amount: refundAmount.toString(),
        Fee: networkFee.toString()
      };
      
      const response = await this.client.submitAndWait(payment, {
        wallet,
        autofill: true
      });
      
      if (response.result.meta.TransactionResult !== 'tesSUCCESS') {
        throw new Error(`Refund transaction failed: ${response.result.meta.TransactionResult}`);
      }
      
      // Update escrow status
      escrow.status = 'cancelled';
      escrow.cancellationTx = response.result.hash;
      escrow.cancelledAt = new Date().toISOString();
      escrow.refundRecipient = recipientAddress;
      
      this.bridgeOperations.set(escrowId, escrow);
      
      this.logger.info('Escrow cancelled successfully', { 
        escrowId, 
        txHash: response.result.hash,
        refundRecipient: recipientAddress,
        amount: xrpl.dropsToXrp(refundAmount.toString())
      });
      
      return {
        success: true,
        txHash: response.result.hash,
        refundAmount: xrpl.dropsToXrp(refundAmount.toString()),
        recipient: recipientAddress
      };
      
    } catch (error) {
      this.logger.error('Cancellation failed', { 
        escrowId, 
        error: error.message 
      });
      throw new Error(`Cancellation failed: ${error.message}`);
    }
  }

  /**
   * Get escrow status and details
   */
  getEscrowStatus(escrowId) {
    const escrow = this.bridgeOperations.get(escrowId);
    
    if (!escrow) {
      return null;
    }
    
    return {
      id: escrow.id,
      status: escrow.status,
      orderHash: escrow.orderHash,
      maker: escrow.maker,
      taker: escrow.taker,
      amount: escrow.amount,
      walletAddress: escrow.wallet.address,
      createdAt: escrow.createdAt,
      fundedAt: escrow.fundedAt,
      withdrawnAt: escrow.withdrawnAt,
      cancelledAt: escrow.cancelledAt
    };
  }

  /**
   * Generate unique escrow ID
   */
  generateEscrowId(orderHash) {
    const timestamp = Date.now();
    const random = crypto.randomBytes(8).toString('hex');
    return `${orderHash.slice(0, 10)}-${timestamp}-${random}`;
  }

  async disconnect() {
    if (this.client && this.client.isConnected()) {
      await this.client.disconnect();
      this.logger.info('Disconnected from XRPL network');
    }
  }
}
