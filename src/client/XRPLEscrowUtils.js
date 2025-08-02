class XRPLEscrowUtils {
  static packTimelocks(timelocks, deployedAt) {
    let packed = BigInt(deployedAt) << 224n;
    for (let i = 0; i < 7; i++) {
      if (timelocks[i] !== undefined) {
        const offset = BigInt(timelocks[i] - deployedAt);
        packed |= offset << BigInt(i * 32);
      }
    }
    return '0x' + packed.toString(16);
  }

  static unpackTimelocks(packedHex) {
    const data = BigInt(packedHex);
    const deployedAt = Number((data >> 224n) & 0xFFFFFFFFn);
    const out = { deployedAt };
    for (let i = 0; i < 7; i++) {
      const offset = Number((data >> BigInt(i * 32)) & 0xFFFFFFFFn);
      out[i] = deployedAt + offset;
    }
    return out;
  }

  static calculateDeposits(token, amount, safetyDeposit) {
    const native = token === '0x0000000000000000000000000000000000000000';
    return {
      xrp: native
        ? (BigInt(amount) + BigInt(safetyDeposit)).toString()
        : safetyDeposit,
      token: native ? '0' : amount,
      total: (BigInt(amount) + BigInt(safetyDeposit)).toString()
    };
  }

  static validateEscrowParams(p) {
    const required = [
      'orderHash','hashlock','maker','taker',
      'token','amount','safetyDeposit','timelocks'
    ];
    for (const f of required) {
      if (!p[f]) throw new Error(`Missing parameter: ${f}`);
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(p.orderHash))
      throw new Error('Invalid orderHash format');
    if (!/^0x[0-9a-fA-F]{64}$/.test(p.hashlock))
      throw new Error('Invalid hashlock format');
    if (!/^r[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(p.maker))
      throw new Error('Invalid maker address');
    if (!/^r[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(p.taker))
      throw new Error('Invalid taker address');
    if (BigInt(p.amount) <= 0n) throw new Error('Amount must be > 0');
    if (BigInt(p.safetyDeposit) < 0n) throw new Error('SafetyDeposit >= 0');
  }
}

module.exports = XRPLEscrowUtils;
