const axios = require('axios');
const crypto = require('crypto');

class XRPLEscrowClient {
  constructor(config = {}) {
    this.baseUrl = config.baseUrl;
    this.timeout = config.timeout || 30000;
    this.retries = config.retries || 3;
    this.http = axios.create({
      baseURL: this.baseUrl,
      timeout: this.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'XRPL-Escrow-Client/1.0.0'
      }
    });
    this.setupInterceptors();
  }

  setupInterceptors() {
    this.http.interceptors.request.use(
      cfg => {
        console.log(`→ ${cfg.method.toUpperCase()} ${cfg.url}`);
        return cfg;
      },
      err => Promise.reject(err)
    );

    this.http.interceptors.response.use(
      res => {
        console.log(`← ${res.status} ${res.config.method.toUpperCase()} ${res.config.url}`);
        return res;
      },
      async err => {
        const { config, response } = err;
        console.error(
          `✗ ${response?.status || 'NETWORK'} ${config.method.toUpperCase()} ${config.url}:`,
          response?.data?.error || err.message
        );

        // initialize retry count
        config.__retryCount = config.__retryCount || 0;
        if (
          config.__retryCount < this.retries &&
          (!response || response.status >= 500 || response.status === 429)
        ) {
          config.__retryCount++;
          const backoff = 2 ** config.__retryCount * 1000;
          console.log(`Retrying (${config.__retryCount}/${this.retries}) after ${backoff}ms…`);
          await new Promise(r => setTimeout(r, backoff));
          return this.http(config);
        }

        return Promise.reject(err);
      }
    );
  }

  static generateSecret() {
    return '0x' + crypto.randomBytes(32).toString('hex');
  }

  static hashSecret(secret) {
    const buf = Buffer.from(secret.replace(/^0x/, ''), 'hex');
    return '0x' + crypto.createHash('sha3-256').update(buf).digest('hex');
  }

  async createDestinationEscrow(data) {
    try {
      const res = await this.http.post('/escrow/create-dst', data);
      return res.data;
    } catch (e) {
      throw this._formatError('createDestinationEscrow', e);
    }
  }

  async fundEscrow(escrowId, fundingData) {
    try {
      const res = await this.http.post(`/escrow/${escrowId}/fund`, fundingData);
      return res.data;
    } catch (e) {
      throw this._formatError('fundEscrow', e);
    }
  }

  async withdraw(escrowId, secret, callerAddress, isPublic = false) {
    try {
      const res = await this.http.post(`/escrow/${escrowId}/withdraw`, {
        secret,
        callerAddress,
        isPublic
      });
      return res.data;
    } catch (e) {
      throw this._formatError('withdraw', e);
    }
  }

  async cancel(escrowId, callerAddress) {
    try {
      const res = await this.http.post(`/escrow/${escrowId}/cancel`, { callerAddress });
      return res.data;
    } catch (e) {
      throw this._formatError('cancel', e);
    }
  }

  async rescueFunds(escrowId, callerAddress, amount) {
    try {
      const res = await this.http.post(`/escrow/${escrowId}/rescue`, {
        callerAddress,
        amount
      });
      return res.data;
    } catch (e) {
      throw this._formatError('rescueFunds', e);
    }
  }

  async getEscrow(escrowId) {
    try {
      const res = await this.http.get(`/escrow/${escrowId}`);
      return res.data;
    } catch (e) {
      throw this._formatError('getEscrow', e);
    }
  }

  async getHealth() {
    try {
      const res = await this.http.get('/health');
      return res.data;
    } catch (e) {
      throw this._formatError('getHealth', e);
    }
  }

  async waitForStatus(escrowId, targetStatus, timeout = 300_000, interval = 2_000) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      try {
        const esc = await this.getEscrow(escrowId);
        if (esc.status === targetStatus) return esc;
        console.log(`Waiting: ${escrowId} is "${esc.status}", target "${targetStatus}"`);
      } catch (e) {
        console.warn('waitForStatus error:', e.message);
      }
      await new Promise(r => setTimeout(r, interval));
    }
    throw new Error(`Timeout waiting for status "${targetStatus}" on ${escrowId}`);
  }

  _formatError(method, e) {
    const err = new Error(`${method} failed: ${e.message}`);
    err.original = e;
    err.response = e.response?.data;
    err.status = e.response?.status;
    return err;
  }
}

module.exports = XRPLEscrowClient;
