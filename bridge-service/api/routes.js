import express from 'express';
import { z } from 'zod';

const router = express.Router();

// Validation schemas
const CreateEscrowRequestSchema = z.object({
  orderHash: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
  hashlock: z.string(),
  maker: z.string(),
  taker: z.string(),
  token: z.string(),
  amount: z.string(),
  safetyDeposit: z.string(),
  timelocks: z.string(),
  type: z.enum(['src', 'dst'])
});

const FundEscrowRequestSchema = z.object({
  fromAddress: z.string(),
  txHash: z.string().regex(/^[A-F0-9]{64}$/i)
});

const WithdrawRequestSchema = z.object({
  secret: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
  recipientAddress: z.string(),
  isPublic: z.boolean().optional()
});

const CancelRequestSchema = z.object({
  recipientAddress: z.string()
});

/**
 * Bridge API Routes
 */
export function createBridgeRoutes(bridgeCore) {
  
  // Health check endpoint
  router.get('/health', (req, res) => {
    res.json({ 
      status: 'healthy', 
      service: 'nuvex-bridge',
      timestamp: new Date().toISOString(),
      version: '2.0.0'
    });
  });

  // Create destination escrow
  router.post('/escrow/destination', async (req, res) => {
    try {
      const params = CreateEscrowRequestSchema.parse(req.body);
      const result = await bridgeCore.createDestinationEscrow(params);
      
      res.status(201).json({
        success: true,
        data: result
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  });

  // Fund escrow
  router.post('/escrow/:escrowId/fund', async (req, res) => {
    try {
      const { escrowId } = req.params;
      const fundingData = FundEscrowRequestSchema.parse(req.body);
      
      const result = await bridgeCore.fundEscrow(escrowId, fundingData);
      
      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  });

  // Withdraw from escrow
  router.post('/escrow/:escrowId/withdraw', async (req, res) => {
    try {
      const { escrowId } = req.params;
      const { secret, recipientAddress, isPublic = false } = WithdrawRequestSchema.parse(req.body);
      
      const result = await bridgeCore.withdraw(escrowId, secret, recipientAddress, isPublic);
      
      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  });

  // Cancel escrow
  router.post('/escrow/:escrowId/cancel', async (req, res) => {
    try {
      const { escrowId } = req.params;
      const { recipientAddress } = CancelRequestSchema.parse(req.body);
      
      const result = await bridgeCore.cancel(escrowId, recipientAddress);
      
      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  });

  // Get escrow status
  router.get('/escrow/:escrowId/status', (req, res) => {
    try {
      const { escrowId } = req.params;
      const status = bridgeCore.getEscrowStatus(escrowId);
      
      if (!status) {
        return res.status(404).json({
          success: false,
          error: 'Escrow not found'
        });
      }
      
      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  });

  // Get bridge statistics
  router.get('/stats', (req, res) => {
    try {
      const totalEscrows = bridgeCore.bridgeOperations.size;
      const escrowsByStatus = {};
      
      for (const escrow of bridgeCore.bridgeOperations.values()) {
        escrowsByStatus[escrow.status] = (escrowsByStatus[escrow.status] || 0) + 1;
      }
      
      res.json({
        success: true,
        data: {
          totalEscrows,
          escrowsByStatus,
          network: bridgeCore.config.network,
          timestamp: new Date().toISOString()
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  });

  return router;
}
