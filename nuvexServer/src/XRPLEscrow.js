const express = require('express');
const cors = require('cors');
const configDefaults = require('./config');
const logger = require('./middleware/logger');
const escrowRoutes = require('./routes/escrow');
const { initializeClient, disconnectClient } = require('./services/escrowService');

class XRPLEscrow {
  constructor(config = {}) {
    this.config = { ...configDefaults, ...config };
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
  }

  setupMiddleware() {
    this.app.use(cors());
    this.app.use(express.json());
    this.app.use(logger);
  }

  setupRoutes() {
    this.app.use('/escrow', escrowRoutes());
    this.app.get('/health', require('./controllers/healthController'));
  }

  async start() {
    await initializeClient(this.config.network);
    this.app.listen(this.config.port, () => console.log(`Server running on port ${this.config.port}`));
  }

  async stop() {
    await disconnectClient();
  }
}

module.exports = XRPLEscrow;