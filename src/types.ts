export interface TrustResult {
  score: number;
  band: string;
  name: string;
}

export interface TrustProvider {
  check(name: string): Promise<TrustResult>;
}

export interface GuardRule {
  /** Minimum trust score required (0-100) */
  minTrust: number;
  /** Tool name patterns — supports * wildcards (e.g. "get_*", "admin_*") */
  tools: string[];
}

export interface RateLimitConfig {
  /** Time window in seconds */
  window: number;
  /** Max requests per window */
  max: number;
}

export interface AuditEntry {
  timestamp: string;
  caller: string;
  method: string;
  tool: string | null;
  trustScore: number;
  trustBand: string;
  allowed: boolean;
  reason: string;
}

export interface AbuseCheckResult {
  reported: boolean;
  report_count: number;
  severity: string;
  recommendation: string;
  reasons: string[];
}

export interface GuardConfig {
  /** Custom trust provider — omit to use AgentScore (default) */
  provider?: TrustProvider;
  /** AgentScore API URL (default: https://agentscores.xyz/api/score) */
  apiUrl?: string;
  /** Header to read caller identity from (default: x-agent-name) */
  identityHeader?: string;
  /** Access rules — first matching rule wins */
  rules?: GuardRule[];
  /** Minimum trust for tools not covered by any rule (default: 0) */
  defaultMinTrust?: number;
  /** Rate limiting per caller */
  rateLimit?: RateLimitConfig;
  /** Trust score cache TTL in ms (default: 300000 = 5 min) */
  cacheTtl?: number;
  /** Audit logging — true for console, or a custom function */
  audit?: boolean | ((entry: AuditEntry) => void);
  /** Allow requests with no caller identity (default: false) */
  allowAnonymous?: boolean;
  /** Check KYA abuse database before allowing access (default: false) */
  abuseCheck?: boolean;
  /** KYA abuse API URL (default: https://agentscores.xyz/api/abuse/check) */
  abuseApiUrl?: string;
  /** Block agents with this recommendation or worse: MONITOR | CAUTION | BLOCK (default: BLOCK) */
  abuseBlockLevel?: 'MONITOR' | 'CAUTION' | 'BLOCK';
}

export interface GuardDecision {
  allowed: boolean;
  reason: string;
  caller: string;
  trustScore: number;
  trustBand: string;
}
