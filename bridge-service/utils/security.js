import crypto from 'crypto';

export class SecurityManager {
  constructor() {
    this.maxEscrowValue = BigInt('1000000000000'); // 1M XRP in drops
    this.minEscrowValue = BigInt('100000'); // 0.1 XRP in drops
    this.allowedTokens = new Set([
      '0x0000000000000000000000000000000000000000', // Native XRP
      // Add other allowed token addresses
    ]);
  }

  /**
   * Validate escrow parameters for security
   */
  validateEscrowParams(params) {
    const { amount, safetyDeposit, token, maker, taker } = params;
    
    // Validate amounts
    const escrowAmount = BigInt(amount);
    const depositAmount = BigInt(safetyDeposit);
    
    if (escrowAmount < this.minEscrowValue) {
      throw new Error(`Escrow amount too small: ${escrowAmount} < ${this.minEscrowValue}`);
    }
    
    if (escrowAmount > this.maxEscrowValue) {
      throw new Error(`Escrow amount too large: ${escrowAmount} > ${this.maxEscrowValue}`);
    }
    
    if (depositAmount > escrowAmount) {
      throw new Error('Safety deposit cannot exceed escrow amount');
    }
    
    // Validate token address
    if (!this.allowedTokens.has(token.toLowerCase())) {
      throw new Error(`Token not allowed: ${token}`);
    }
    
    // Validate XRPL addresses
    if (!this.isValidXRPLAddress(maker)) {
      throw new Error(`Invalid maker XRPL address: ${maker}`);
    }
    
    if (!this.isValidXRPLAddress(taker)) {
      throw new Error(`Invalid taker XRPL address: ${taker}`);
    }
    
    // Prevent self-transactions
    if (maker === taker) {
      throw new Error('Maker and taker cannot be the same address');
    }
    
    return true;
  }

  /**
   * Validate XRPL address format
   */
  isValidXRPLAddress(address) {
    // Basic XRPL address validation
    return /^r[a-zA-Z0-9]{24,34}$/.test(address);
  }

  /**
   * Generate secure random bytes
   */
  generateSecureRandom(length = 32) {
    return crypto.randomBytes(length);
  }

  /**
   * Rate limiting validation
   */
  validateRateLimit(clientId, action, windowMs = 60000, maxRequests = 10) {
    // In production, implement proper rate limiting with Redis or similar
    // This is a simplified in-memory version
    if (!this.rateLimitStore) {
      this.rateLimitStore = new Map();
    }
    
    const key = `${clientId}:${action}`;
    const now = Date.now();
    const windowStart = now - windowMs;
    
    if (!this.rateLimitStore.has(key)) {
      this.rateLimitStore.set(key, []);
    }
    
    const requests = this.rateLimitStore.get(key);
    
    // Remove old requests outside the window
    const validRequests = requests.filter(timestamp => timestamp > windowStart);
    
    if (validRequests.length >= maxRequests) {
      throw new Error(`Rate limit exceeded for action: ${action}`);
    }
    
    validRequests.push(now);
    this.rateLimitStore.set(key, validRequests);
    
    return true;
  }

  /**
   * Sanitize input data
   */
  sanitizeInput(data) {
    if (typeof data === 'string') {
      return data.trim().replace(/[<>\"']/g, '');
    }
    
    if (typeof data === 'object' && data !== null) {
      const sanitized = {};
      for (const [key, value] of Object.entries(data)) {
        sanitized[key] = this.sanitizeInput(value);
      }
      return sanitized;
    }
    
    return data;
  }
}
