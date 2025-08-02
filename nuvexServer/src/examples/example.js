// src/examples/example.js
const xrpl = require('xrpl');
const XRPLEscrowClient = require('../client/XRPLEscrowClient');
const XRPLEscrowUtils = require('../client/XRPLEscrowUtils');
const config = require('../config');

async function runCompleteSwapExample() {
  console.log('🚀 Starting Cross-Chain Atomic Swap Example');

  // TEE server client
  const tee = new XRPLEscrowClient({
    baseUrl: process.env.TEE_URL || `http://localhost:${config.port}`
  });

  // XRPL connection
  const xclient = new xrpl.Client(config.network);
  await xclient.connect();

  // Fund a new test wallet for taker
  const { wallet } = await xclient.fundWallet();
  const takerWallet = wallet;
  console.log(`Taker XRPL: ${takerWallet.address}`);

  // 1) Secret & hashlock
  const secret = XRPLEscrowClient.generateSecret();
  const hashlock = XRPLEscrowClient.hashSecret(secret);

  // 2) Timelocks (seconds from now)
  const now = Math.floor(Date.now() / 1000);
  const timelocks = {
    0: now + 300,   1: now + 600,
    2: now + 1800,  3: now + 2400,
    4: now + 120,   5: now + 480,
    6: now + 1200
  };
  const packed = XRPLEscrowUtils.packTimelocks(timelocks, now);

  // 3) Create escrow
  const params = {
    orderHash: '0x' + '1'.repeat(64),
    hashlock,
    maker: 'rMaker12345...',
    taker: takerWallet.address,
    token: '0x0000000000000000000000000000000000000000',
    amount: '1000000',
    safetyDeposit: '100000',
    timelocks: packed,
    type: 'dst'
  };
  XRPLEscrowUtils.validateEscrowParams(params);

  const esc = await tee.createDestinationEscrow(params);
  console.log('Escrow created:', esc);

  // 4) Fund escrow
  const payment = {
    TransactionType: 'Payment',
    Account: takerWallet.address,
    Destination: esc.walletAddress,
    Amount: esc.requiredDeposit.xrp
  };
  const prepared = await xclient.autofill(payment);
  const signed = takerWallet.sign(prepared);
  const fundRes = await xclient.submitAndWait(signed.tx_blob);
  await tee.fundEscrow(esc.escrowId, {
    fromAddress: takerWallet.address,
    txHash: fundRes.result.hash
  });
  console.log('Escrow funded');

  // 5) Wait for DstWithdrawal
  const wait = timelocks[4] - Math.floor(Date.now()/1000);
  if (wait > 0) await new Promise(r => setTimeout(r, wait * 1000));

  // 6) Withdraw
  const wd = await tee.withdraw(
    esc.escrowId,
    secret,
    takerWallet.address
  );
  console.log('Withdrawal result:', wd);

  // 7) Final state
  const final = await tee.getEscrow(esc.escrowId);
  console.log('Final escrow:', final);

  await xclient.disconnect();
}

if (require.main === module) {
  runCompleteSwapExample().catch(e => console.error(e));
}

module.exports = { runCompleteSwapExample };
