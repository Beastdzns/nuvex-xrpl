const { network, port, rescueDelay } = require('./config');
const XRPLEScrow = require('./XRPLEscrow');

const config = {
    network: network,
    port: port,
    rescueDelay: rescueDelay ? parseInt(process.env.RESCUE_DELAY) : undefined
};

const server = new XRPLEScrow(config);

async function startServer() {
    try {
        console.log("[INFO] Starting XRPL Escrow Server...");
        await server.start();
        console.log("[SUCCESS] Server started on Network: ", config.network);
    } catch(error){
        console.log("[ERROR] Failed to start the server: ", error);
        process.exit(1);
    }
}

async function shutdown() {
  try {
    console.log('\n[INFO] Received termination signal. Shutting down...');
    await server.stop();
    console.log('[SUCCESS] Server stopped gracefully.');
    process.exit(0);
  } catch (error) {
    console.error('[ERROR] Error while shutting down the server:', error);
    process.exit(1);
  }
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Start the server
startServer();