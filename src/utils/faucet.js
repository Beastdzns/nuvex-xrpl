const xrpl = require('xrpl');

async function refuelWalletFromFaucet(wallet, client, minBalance = 5) {
  let c = client;
  let disconnect = false;
  if (!c) { c = new xrpl.Client('wss://s.altnet.rippletest.net:51233'); await c.connect(); disconnect = true; }
  try {
    const resp = await c.request({ command: 'account_info', account: wallet.address, ledger_index: 'validated' });
    const bal = Number(xrpl.dropsToXrp(resp.result.account_data.Balance));
    if (bal >= minBalance) return;
  } catch {}
  await c.fundWallet(wallet);
  if (disconnect) await c.disconnect();
}

module.exports = { refuelWalletFromFaucet };