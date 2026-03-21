import type { TrustResult, TrustProvider } from './types.js';

interface CacheEntry {
  result: TrustResult;
  expires: number;
}

export class TrustCache {
  private cache = new Map<string, CacheEntry>();
  private ttl: number;

  constructor(ttlMs: number = 300_000) {
    this.ttl = ttlMs;
  }

  get(key: string): TrustResult | null {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expires) {
      this.cache.delete(key);
      return null;
    }
    return entry.result;
  }

  set(key: string, result: TrustResult): void {
    this.cache.set(key, { result, expires: Date.now() + this.ttl });
  }

  clear(): void {
    this.cache.clear();
  }
}

export class AgentScoreProvider implements TrustProvider {
  private apiUrl: string;
  private cache: TrustCache;

  constructor(apiUrl?: string, cacheTtl?: number) {
    this.apiUrl = apiUrl ?? 'https://agentscores.xyz/api/score';
    this.cache = new TrustCache(cacheTtl);
  }

  async check(name: string): Promise<TrustResult> {
    const cached = this.cache.get(name);
    if (cached) return cached;

    try {
      const res = await fetch(`${this.apiUrl}?name=${encodeURIComponent(name)}`);
      if (!res.ok) {
        return { score: 0, band: 'UNKNOWN', name };
      }
      const data = await res.json() as any;
      const result: TrustResult = {
        score: data.score?.effective ?? data.score?.raw ?? 0,
        band: data.score?.band ?? 'UNKNOWN',
        name: data.agent?.name ?? name,
      };
      this.cache.set(name, result);
      return result;
    } catch {
      // Fail closed — unreachable API means score 0
      return { score: 0, band: 'ERROR', name };
    }
  }
}
