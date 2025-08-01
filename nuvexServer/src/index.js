require('dotenv').config();

const XRPLEScrow = require('./XRPLEscrow');

const config = {
    network: process.env.XRPL_NETWORK,
    port: process.env.PORT,
    rescueDelay: process.env.RESCUE_DELAY ? parseInt(process.env.RESCUE_DELAY) : undefined
};

const server = 