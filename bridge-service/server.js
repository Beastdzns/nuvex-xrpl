import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { NuvexBridgeCore } from './core/bridge-engine.js';
import { createBridgeRoutes } from './api/routes.js';
import { Logger } from './utils/logger.js';

/**
 * Nuvex Bridge Service Server
 * Main server application for cross-chain bridge operations
 */
class NuvexBridgeServer {
  constructor(config = {}) {
    this.logger = new Logger('BridgeServer');
    this.config = {
      port: config.port || process.env.PORT || 3000,
      network: config.network || process.env.XRPL_NETWORK || 'wss://s.altnet.rippletest.net:51233',
      corsOrigin: config.corsOrigin || process.env.CORS_ORIGIN || '*',
      rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100 // limit each IP to 100 requests per windowMs
      },
      ...config
    };
    
    this.app = express();
    this.bridgeCore = null;
    this.server = null;
  }

  async initialize() {
    try {
      // Initialize bridge core
      this.bridgeCore = new NuvexBridgeCore({
        network: this.config.network
      });
      
      const connected = await this.bridgeCore.initialize();
      if (!connected) {
        throw new Error('Failed to connect to XRPL network');
      }
      
      // Setup middleware
      this.setupMiddleware();
      
      // Setup routes
      this.setupRoutes();
      
      // Setup error handling
      this.setupErrorHandling();
      
      this.logger.info('Nuvex Bridge Server initialized successfully');
      return true;
      
    } catch (error) {
      this.logger.error('Failed to initialize bridge server', { error: error.message });
      return false;
    }
  }

  setupMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"]
        }
      }
    }));
    
    // CORS configuration
    this.app.use(cors({
      origin: this.config.corsOrigin,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));
    
    // Rate limiting
    const limiter = rateLimit({
      windowMs: this.config.rateLimit.windowMs,
      max: this.config.rateLimit.max,
      message: {
        error: 'Too many requests from this IP, please try again later'
      },
      standardHeaders: true,
      legacyHeaders: false
    });
    this.app.use('/api/', limiter);
    
    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    
    // Request logging
    this.app.use((req, res, next) => {
      const start = Date.now();
      res.on('finish', () => {
        const duration = Date.now() - start;
        this.logger.info('HTTP Request', {
          method: req.method,
          url: req.url,
          status: res.statusCode,
          duration: `${duration}ms`,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
      });
      next();
    });
  }

  setupRoutes() {
    // API routes
    this.app.use('/api/v1', createBridgeRoutes(this.bridgeCore));
    
    // Root endpoint
    this.app.get('/', (req, res) => {
      res.json({
        service: 'Nuvex Cross-Chain Bridge',
        version: '2.0.0',
        status: 'operational',
        network: this.config.network,
        endpoints: {
          health: '/api/v1/health',
          createEscrow: 'POST /api/v1/escrow/destination',
          fundEscrow: 'POST /api/v1/escrow/:id/fund',
          withdraw: 'POST /api/v1/escrow/:id/withdraw',
          cancel: 'POST /api/v1/escrow/:id/cancel',
          status: 'GET /api/v1/escrow/:id/status',
          stats: 'GET /api/v1/stats'
        }
      });
    });
    
    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        path: req.originalUrl
      });
    });
  }

  setupErrorHandling() {
    // Global error handler
    this.app.use((error, req, res, next) => {
      this.logger.error('Unhandled error', {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method
      });
      
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { details: error.message })
      });
    });
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      this.logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
      this.gracefulShutdown();
    });
    
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      this.logger.error('Unhandled Rejection', { reason, promise });
      this.gracefulShutdown();
    });
    
    // Handle termination signals
    process.on('SIGTERM', () => {
      this.logger.info('SIGTERM received, starting graceful shutdown');
      this.gracefulShutdown();
    });
    
    process.on('SIGINT', () => {
      this.logger.info('SIGINT received, starting graceful shutdown');
      this.gracefulShutdown();
    });
  }

  async start() {
    try {
      const initialized = await this.initialize();
      if (!initialized) {
        throw new Error('Failed to initialize server');
      }
      
      this.server = this.app.listen(this.config.port, () => {
        this.logger.info(`Nuvex Bridge Server running on port ${this.config.port}`, {
          network: this.config.network,
          environment: process.env.NODE_ENV || 'development'
        });
      });
      
      return this.server;
      
    } catch (error) {
      this.logger.error('Failed to start server', { error: error.message });
      process.exit(1);
    }
  }

  async gracefulShutdown() {
    this.logger.info('Starting graceful shutdown...');
    
    if (this.server) {
      this.server.close((error) => {
        if (error) {
          this.logger.error('Error during server shutdown', { error: error.message });
        } else {
          this.logger.info('HTTP server closed');
        }
      });
    }
    
    if (this.bridgeCore) {
      await this.bridgeCore.disconnect();
    }
    
    this.logger.info('Graceful shutdown completed');
    process.exit(0);
  }
}

// Start server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = new NuvexBridgeServer();
  server.start();
}

export { NuvexBridgeServer };
