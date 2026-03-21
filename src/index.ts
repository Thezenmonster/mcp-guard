import { AgentScoreProvider } from './trust.js';
import type {
  GuardConfig,
  GuardDecision,
  GuardRule,
  AuditEntry,
  TrustProvider,
  TrustResult,
  RateLimitConfig,
} from './types.js';

export type { GuardConfig, GuardDecision, GuardRule, AuditEntry, TrustProvider, TrustResult, RateLimitConfig };
export { AgentScoreProvider } from './trust.js';
export { TrustCache } from './trust.js';

// --- Glob matching for tool names ---

function matchPattern(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return pattern === value;
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(value);
}

// --- In-memory sliding window rate limiter ---

class RateLimiter {
  private windows = new Map<string, number[]>();
  private windowMs: number;
  private max: number;

  constructor(config: RateLimitConfig) {
    this.windowMs = config.window * 1000;
    this.max = config.max;
  }

  check(key: string): boolean {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const timestamps = (this.windows.get(key) ?? []).filter(t => t > cutoff);
    if (timestamps.length >= this.max) {
      this.windows.set(key, timestamps);
      return false;
    }
    timestamps.push(now);
    this.windows.set(key, timestamps);
    return true;
  }

  reset(key?: string): void {
    if (key) this.windows.delete(key);
    else this.windows.clear();
  }
}

// --- McpGuard ---

export class McpGuard {
  private provider: TrustProvider;
  private rules: GuardRule[];
  private defaultMinTrust: number;
  private identityHeader: string;
  private rateLimiter: RateLimiter | null;
  private auditFn: ((entry: AuditEntry) => void) | null;
  private allowAnonymous: boolean;

  constructor(config: GuardConfig = {}) {
    this.provider = config.provider ?? new AgentScoreProvider(config.apiUrl, config.cacheTtl);
    this.rules = config.rules ?? [];
    this.defaultMinTrust = config.defaultMinTrust ?? 0;
    this.identityHeader = (config.identityHeader ?? 'x-agent-name').toLowerCase();
    this.allowAnonymous = config.allowAnonymous ?? false;
    this.rateLimiter = config.rateLimit ? new RateLimiter(config.rateLimit) : null;

    if (config.audit === true) {
      this.auditFn = (entry) => {
        const icon = entry.allowed ? 'ALLOW' : 'DENY';
        console.log(`[mcp-guard] ${icon} ${entry.caller} → ${entry.tool ?? entry.method} (score: ${entry.trustScore}, band: ${entry.trustBand}) ${entry.reason}`);
      };
    } else if (typeof config.audit === 'function') {
      this.auditFn = config.audit;
    } else {
      this.auditFn = null;
    }
  }

  /**
   * Check if a caller should be allowed to call a specific tool.
   */
  async check(caller: string, tool: string): Promise<GuardDecision> {
    const trust = await this.provider.check(caller);
    const minTrust = this.getMinTrust(tool);
    const allowed = trust.score >= minTrust;

    return {
      allowed,
      reason: allowed
        ? `score ${trust.score} >= ${minTrust} required for ${tool}`
        : `score ${trust.score} < ${minTrust} required for ${tool}`,
      caller,
      trustScore: trust.score,
      trustBand: trust.band,
    };
  }

  /**
   * Express/Connect middleware. Intercepts tools/call requests
   * and enforces trust-based access control.
   *
   * Requires body to be parsed (use express.json() before this middleware).
   */
  middleware() {
    return async (req: any, res: any, next: any) => {
      if (req.method !== 'POST') return next();

      const body = req.body;
      if (!body || body.method !== 'tools/call') return next();

      const tool = body.params?.name ?? 'unknown';
      const caller = this.getCaller(req);

      // Anonymous check
      if (!caller) {
        if (this.allowAnonymous) return next();
        const entry = this.buildEntry('anonymous', body.method, tool, 0, 'ANONYMOUS', false, 'no caller identity provided');
        this.audit(entry);
        return this.deny(res, body.id, entry.reason);
      }

      // Rate limit check
      if (this.rateLimiter && !this.rateLimiter.check(caller)) {
        const entry = this.buildEntry(caller, body.method, tool, -1, 'RATE_LIMITED', false, 'rate limit exceeded');
        this.audit(entry);
        return this.deny(res, body.id, entry.reason, 429);
      }

      // Trust check
      const decision = await this.check(caller, tool);
      const entry = this.buildEntry(caller, body.method, tool, decision.trustScore, decision.trustBand, decision.allowed, decision.reason);
      this.audit(entry);

      if (!decision.allowed) {
        return this.deny(res, body.id, decision.reason);
      }

      next();
    };
  }

  /**
   * Wrap any request handler with trust-based access control.
   * Works with any HTTP framework.
   */
  wrap(handler: (req: any, res: any) => any) {
    const mw = this.middleware();
    return (req: any, res: any) => {
      mw(req, res, () => handler(req, res));
    };
  }

  private getMinTrust(tool: string): number {
    for (const rule of this.rules) {
      for (const pattern of rule.tools) {
        if (matchPattern(pattern, tool)) return rule.minTrust;
      }
    }
    return this.defaultMinTrust;
  }

  private getCaller(req: any): string | null {
    const fromHeader = req.headers?.[this.identityHeader];
    if (fromHeader) return String(fromHeader);

    try {
      const url = new URL(req.url ?? '/', `http://${req.headers?.host ?? 'localhost'}`);
      return url.searchParams.get('agent');
    } catch {
      return null;
    }
  }

  private buildEntry(
    caller: string, method: string, tool: string | null,
    trustScore: number, trustBand: string, allowed: boolean, reason: string,
  ): AuditEntry {
    return { timestamp: new Date().toISOString(), caller, method, tool, trustScore, trustBand, allowed, reason };
  }

  private audit(entry: AuditEntry): void {
    if (this.auditFn) this.auditFn(entry);
  }

  private deny(res: any, id: any, reason: string, status: number = 403): void {
    res.status(status).json({
      jsonrpc: '2.0',
      id: id ?? null,
      error: {
        code: status === 429 ? -32029 : -32001,
        message: `[mcp-guard] Access denied: ${reason}`,
      },
    });
  }
}
