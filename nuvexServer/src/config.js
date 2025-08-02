require('dotenv').config()
module.exports = {
  network: process.env.XRPL_NETWORK,
  port: process.env.PORT,
  rescueDelay: process.env.RESCUE_DELAY
};