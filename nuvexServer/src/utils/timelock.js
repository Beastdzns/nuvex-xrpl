function parseTimelocks(packed, deployedAt) {
  const d = BigInt(packed);
  const out = {};
  for (let i = 0; i < 7; i++) {
    const shift = BigInt(i * 32);
    out[i] = deployedAt + Number((d >> shift) & 0xFFFFFFFFn);
  }
  return out;
}
function validateTimeWindow(escrow, stage, requireBefore = null, offset = 0) {
  const now = Math.floor(Date.now()/1000) + offset;
  if (now < escrow.timelocks[stage]) throw new Error(`Action not allowed until ${new Date(escrow.timelocks[stage]*1000)}`);
  if (requireBefore !== null && now >= escrow.timelocks[requireBefore]) throw new Error(`Window expired at ${new Date(escrow.timelocks[requireBefore]*1000)}`);
}
module.exports = { parseTimelocks, validateTimeWindow };
