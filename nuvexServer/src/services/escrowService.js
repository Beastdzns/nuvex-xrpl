const xrpl = require('xrpl');
const crypto = require('crypto');
const { mykeccak256 } = require('../utils/hash');
const { parseTimelocks, validateTimeWindow } = require('../utils/timelock');
const { refuelWalletFromFaucet } = require('../utils/faucet');

let client;
const escrows = new Map();
const walletSeeds = new Map();

async function initializeClient(network) {
  client = new xrpl.Client(network);
  await client.connect();
  console.log(`Connected to XRPL ${network}`);
}

async function disconnectClient() {
  if (client) await client.disconnect();
}

async function createDst(params) {
  const { orderHash, hashlock, maker, taker, token, amount, safetyDeposit, timelocks, type } = params;
  const wallet = xrpl.Wallet.fromEntropy(Buffer.from('ripple-escrow-wallet', 'utf8'));
  await refuelWalletFromFaucet(wallet, client);

  const deployedAt = Math.floor(Date.now() / 1000);
  const parsed = parseTimelocks(timelocks, deployedAt);
  const id = crypto.randomUUID();
  const escrow = {
    id,
    orderHash,
    hashlock,
    maker,
    taker,
    token,
    amount: BigInt(amount),
    safetyDeposit: BigInt(safetyDeposit),
    timelocks: parsed,
    deployedAt,
    wallet: { address: wallet.address, publicKey: wallet.publicKey },
    status: 'created',
    type
  };
  escrows.set(id, escrow);
  walletSeeds.set(id, wallet.seed);

  return {
    escrowId: id,
    walletAddress: wallet.address,
    requiredDeposit: {
      xrp: token === '0x0000000000000000000000000000000000000000'
        ? (escrow.amount + escrow.safetyDeposit).toString()
        : escrow.safetyDeposit.toString(),
      token: token !== '0x0000000000000000000000000000000000000000' ? escrow.amount.toString() : '0'
    },
    timelocks: parsed
  };
}

async function fund(id, txHash) {
  const escrow = escrows.get(id);
  if (!escrow) throw new Error('Escrow not found');

  const hashes = txHash.includes(',') ? txHash.split(',') : [txHash];
  let total = 0n;
  const verified = [];

  for (const h of hashes) {
    const tx = await client.request({ command: 'tx', transaction: h });
    if (tx.result.tx_json.TransactionType !== 'Payment')
      throw new Error(`Invalid tx type for ${h}`);
    if (tx.result.tx_json.Destination !== escrow.wallet.address)
      throw new Error(`Payment ${h} not to escrow address`);
    const amt = BigInt(tx.result.meta.delivered_amount);
    total += amt;
    verified.push({ txHash: h, amount: amt.toString() });
  }

  const required = escrow.token === '0x0000000000000000000000000000000000000000'
    ? escrow.amount + escrow.safetyDeposit
    : escrow.safetyDeposit;

  if (total < required) throw new Error(`Insufficient: required ${required}, got ${total}`);

  escrow.status = 'funded';
  escrow.fundingTxs = hashes;
  return { message: 'Escrow funded', escrowId: id, totalAmountReceived: total.toString(), verifiedTxs: verified };
}

async function withdraw(id, secret, callerAddress, isPublic = false) {
  const escrow = escrows.get(id);
  if (!escrow) throw new Error('Escrow not found');
  if (escrow.status !== 'funded') throw new Error('Escrow not funded');

  if (mykeccak256(secret).toLowerCase() !== escrow.hashlock.toLowerCase())
    throw new Error('Invalid secret');

  if (!isPublic) {
    if (callerAddress !== escrow.taker) throw new Error('Only taker can withdraw privately');
    validateTimeWindow(escrow, 4, 6, 11);
  } else {
    validateTimeWindow(escrow, 5, 6);
  }

  const wallet = xrpl.Wallet.fromSeed(walletSeeds.get(id));

  // main payment
  const pay = { TransactionType: 'Payment', Account: wallet.address, Destination: escrow.maker, Amount: escrow.amount.toString() };
  const prep = await client.autofill(pay);
  const signed = wallet.sign(prep);
  const result = await client.submitAndWait(signed.tx_blob);
  if (result.result.meta.TransactionResult !== 'tesSUCCESS')
    throw new Error(`Txn failed: ${result.result.meta.TransactionResult}`);

  escrow.status = 'withdrawn';
  escrow.withdrawTx = result.result.hash;
  escrow.secret = secret;

  // safety deposit back
  if (escrow.safetyDeposit > 0n) {
    const safe = { TransactionType: 'Payment', Account: wallet.address, Destination: callerAddress, Amount: escrow.safetyDeposit.toString() };
    const p2 = await client.autofill(safe);
    const s2 = wallet.sign(p2);
    await client.submitAndWait(s2.tx_blob);
  }

  return { message: 'Withdrawal successful', txHash: result.result.hash, secret, amount: escrow.amount.toString() };
}

async function cancel(id, callerAddress) {
  const escrow = escrows.get(id);
  if (!escrow) throw new Error('Escrow not found');
  if (escrow.status !== 'funded') throw new Error('Cannot cancel');
  if (callerAddress !== escrow.taker) throw new Error('Only taker can cancel');
  validateTimeWindow(escrow, 6, null, 125);

  const wallet = xrpl.Wallet.fromSeed(walletSeeds.get(id));
  const refunds = [];

  if (escrow.type === 'dst') {
    const amt = (escrow.amount + escrow.safetyDeposit).toString();
    const p = { TransactionType: 'Payment', Account: wallet.address, Destination: escrow.taker, Amount: amt };
    const pr = await client.autofill(p);
    const s = wallet.sign(pr);
    const r = await client.submitAndWait(s.tx_blob);
    if (r.result.meta.TransactionResult !== 'tesSUCCESS')
      throw new Error(`Cancel failed: ${r.result.meta.TransactionResult}`);
    refunds.push({ recipient: escrow.taker, amount: amt, txHash: r.result.hash });
  } else {
    // src type: amount->maker, safety->taker
    if (escrow.amount > 0n) {
      const p1 = { TransactionType: 'Payment', Account: wallet.address, Destination: escrow.maker, Amount: escrow.amount.toString() };
      const pr1 = await client.autofill(p1);
      const s1 = wallet.sign(pr1);
      const r1 = await client.submitAndWait(s1.tx_blob);
      if (r1.result.meta.TransactionResult !== 'tesSUCCESS')
        throw new Error(`Maker refund failed: ${r1.result.meta.TransactionResult}`);
      refunds.push({ recipient: escrow.maker, amount: escrow.amount.toString(), txHash: r1.result.hash });
    }
    if (escrow.safetyDeposit > 0n) {
      const p2 = { TransactionType: 'Payment', Account: wallet.address, Destination: escrow.taker, Amount: escrow.safetyDeposit.toString() };
      const pr2 = await client.autofill(p2);
      const s2 = wallet.sign(pr2);
      const r2 = await client.submitAndWait(s2.tx_blob);
      if (r2.result.meta.TransactionResult !== 'tesSUCCESS')
        throw new Error(`Safety refund failed: ${r2.result.meta.TransactionResult}`);
      refunds.push({ recipient: escrow.taker, amount: escrow.safetyDeposit.toString(), txHash: r2.result.hash });
    }
  }

  escrow.status = 'cancelled';
  escrow.cancelTxs = refunds;
  return { message: 'Escrow cancelled', escrowType: escrow.type, cancelTxs: refunds, totalRefunded: (escrow.amount + escrow.safetyDeposit).toString() };
}

async function rescue(id, callerAddress, amount) {
  const escrow = escrows.get(id);
  if (!escrow) throw new Error('Escrow not found');
  if (callerAddress !== escrow.taker) throw new Error('Only taker can rescue');
  const start = escrow.deployedAt + parseInt(process.env.RESCUE_DELAY || escrow.rescueDelay);
  if (Math.floor(Date.now()/1000) < start)
    throw new Error(`Rescue not available until ${new Date(start*1000)}`);

  const wallet = xrpl.Wallet.fromSeed(walletSeeds.get(id));
  const p = { TransactionType: 'Payment', Account: wallet.address, Destination: callerAddress, Amount: amount };
  const pr = await client.autofill(p);
  const s = wallet.sign(pr);
  const r = await client.submitAndWait(s.tx_blob);
  if (r.result.meta.TransactionResult !== 'tesSUCCESS')
    throw new Error(`Rescue failed: ${r.result.meta.TransactionResult}`);

  return { message: 'Funds rescued', txHash: r.result.hash, amount };
}

function getEscrow(id) {
  const e = escrows.get(id);
  if (!e) throw new Error('Escrow not found');
  return {
    ...e,
    amount: e.amount.toString(),
    safetyDeposit: e.safetyDeposit.toString()
  };
}

module.exports = {
  initializeClient,
  disconnectClient,
  escrows,
  client,
  createDst,
  fund,
  withdraw,
  cancel,
  rescue,
  getEscrow
};