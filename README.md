# mcp-guard

**KYA (Know Your Agent)** security middleware for MCP servers. Abuse database, trust-based access control, rate limiting, and audit logging.

**Zero dependencies. Works with any Node.js HTTP framework. Part of the [KYA verification system](https://agentscores.xyz).**

[![npm](https://img.shields.io/npm/v/mcp-trust-guard)](https://www.npmjs.com/package/mcp-trust-guard)
[![license](https://img.shields.io/npm/l/mcp-trust-guard)](https://github.com/Thezenmonster/mcp-guard/blob/main/LICENSE)

---

## The Problem

MCP servers have no security layer. Any client can call any tool — there's no identity verification, no access control, no rate limiting, no audit trail. As AI agents begin calling MCP tools autonomously, this is a critical gap.

`mcp-guard` adds KYA verification to any MCP HTTP server — abuse database checks, trust-based access control, and audit logging in three lines of code.

## Install

```bash
npm install mcp-trust-guard
```

## Quick Start

```typescript
import express from 'express';
import { McpGuard } from 'mcp-trust-guard';

const guard = new McpGuard({
  rules: [
    { minTrust: 0,  tools: ['get_*', 'list_*', 'search_*'] },
    { minTrust: 30, tools: ['create_*', 'update_*'] },
    { minTrust: 60, tools: ['delete_*', 'admin_*'] },
  ],
  rateLimit: { window: 60, max: 30 },
  audit: true,
});

const app = express();
app.use(express.json());
app.use('/mcp', guard.middleware());
// ... your MCP server handler
```

Every `tools/call` request is now verified against the caller's trust score. Read-only tools are open. Write tools need a score of 30+. Destructive tools need 60+.

## How It Works

```
                                    ┌──────────────┐
Request ──→ Extract Identity ──→ Rate Limit ──→ │  Trust Check │ ──→ Rule Match ──→ Allow/Deny
             (header)            (per caller)    │ (AgentScore) │    (tool pattern)
                                                 └──────────────┘
```

1. **Identity** — Reads the caller's agent name from the `x-agent-name` header (configurable)
2. **Rate Limit** — Sliding window per caller. Rejects with JSON-RPC error if exceeded
3. **Trust Check** — Looks up the caller's trust score via [AgentScore](https://agentscores.xyz) (5-min cache, fail-closed)
4. **Rule Match** — Matches the requested tool against your rules using glob patterns. First match wins
5. **Allow/Deny** — If the caller's score meets the rule's minimum, the request passes through. Otherwise, a JSON-RPC error is returned

## Features

### Trust-Based Access Control

Define tiered access based on trust scores:

```typescript
const guard = new McpGuard({
  rules: [
    { minTrust: 0,  tools: ['read_*'] },      // Public — anyone can read
    { minTrust: 20, tools: ['query_*'] },      // Low bar — basic queries
    { minTrust: 40, tools: ['write_*'] },      // Verified agents only
    { minTrust: 70, tools: ['transfer_*'] },   // High trust — financial ops
  ],
  defaultMinTrust: 10, // Tools not matching any rule require score >= 10
});
```

### Tool Name Patterns

Rules use glob patterns with `*` wildcards:

```typescript
{ minTrust: 30, tools: ['create_*', 'update_*'] }    // Matches create_user, update_record
{ minTrust: 60, tools: ['admin_*'] }                   // Matches admin_delete, admin_config
{ minTrust: 0,  tools: ['get_status'] }                // Exact match only
{ minTrust: 50, tools: ['*'] }                         // Catch-all
```

### Rate Limiting

In-memory sliding window per caller:

```typescript
const guard = new McpGuard({
  rateLimit: {
    window: 60,  // 60-second window
    max: 30,     // 30 requests per window per caller
  },
});
```

### Audit Logging

Console logging:

```typescript
const guard = new McpGuard({ audit: true });
// [mcp-guard] ALLOW EmberFoundry → get_status (score: 42, band: MODERATE TRUST) score 42 >= 0 required for get_status
// [mcp-guard] DENY  untrusted-bot → admin_delete (score: 3, band: UNVERIFIED) score 3 < 60 required for admin_delete
```

Custom audit handler:

```typescript
const guard = new McpGuard({
  audit: (entry) => {
    db.insert('audit_log', entry);
    if (!entry.allowed) alerting.notify(`Blocked ${entry.caller} from ${entry.tool}`);
  },
});
```

### Direct Trust Checks

Use the guard programmatically without middleware:

```typescript
const guard = new McpGuard();

const decision = await guard.check('EmberFoundry', 'transfer_funds');
// { allowed: false, reason: 'score 14 < 70 required for transfer_funds', caller: 'EmberFoundry', trustScore: 14, trustBand: 'UNVERIFIED' }
```

### Custom Trust Providers

Use any trust source — not just AgentScore:

```typescript
import { McpGuard, TrustProvider, TrustResult } from 'mcp-trust-guard';

const myProvider: TrustProvider = {
  async check(name: string): Promise<TrustResult> {
    const score = await myDatabase.getAgentScore(name);
    return { score, band: score > 50 ? 'TRUSTED' : 'UNTRUSTED', name };
  },
};

const guard = new McpGuard({ provider: myProvider });
```

### Wrapping Any Handler

Not using Express? Wrap any request handler:

```typescript
const protectedHandler = guard.wrap(mcpHandler);
http.createServer(protectedHandler).listen(3000);
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `provider` | `TrustProvider` | AgentScore | Custom trust score provider |
| `apiUrl` | `string` | `https://agentscores.xyz/api/score` | AgentScore API endpoint |
| `identityHeader` | `string` | `x-agent-name` | Header containing caller identity |
| `rules` | `GuardRule[]` | `[]` | Access rules (first match wins) |
| `defaultMinTrust` | `number` | `0` | Min trust when no rule matches |
| `rateLimit` | `{ window, max }` | none | Rate limit config (seconds, count) |
| `cacheTtl` | `number` | `300000` | Trust cache TTL in ms (5 min) |
| `audit` | `boolean \| function` | `false` | Enable audit logging |
| `allowAnonymous` | `boolean` | `false` | Allow requests without identity |

## Identifying Callers

By default, `mcp-guard` reads the caller's identity from the `x-agent-name` HTTP header. MCP clients should include this header when making requests:

```bash
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "x-agent-name: MyAgent" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_data"}}'
```

You can change the header name:

```typescript
const guard = new McpGuard({ identityHeader: 'authorization' });
```

Or use query parameters as a fallback — `?agent=MyAgent` is checked automatically.

## FAQ

**What if the trust API is unreachable?**
The agent gets a score of 0. Fail-closed by default. If your rules allow `minTrust: 0` for some tools, those still work.

**Does it work with stdio MCP servers?**
No — stdio servers run locally and don't need network-level security. `mcp-guard` is for HTTP/SSE MCP servers that accept remote connections.

**Does it modify the MCP request?**
No. It only inspects `tools/call` requests. All other MCP methods (`tools/list`, `resources/read`, etc.) pass through untouched. When a request is allowed, it continues to your handler unchanged.

**Can I use my own scoring system?**
Yes. Implement the `TrustProvider` interface (one method: `check(name) → { score, band, name }`) and pass it in the config.

## KYA Abuse Database (v0.2.0+)

Block agents that have been reported for abuse — data exfiltration, prompt injection, unauthorized access, and more. Community-driven, free, no API key.

```typescript
const guard = new McpGuard({
  abuseCheck: true,                // Enable abuse database checks
  abuseBlockLevel: 'CAUTION',      // Block at MONITOR, CAUTION, or BLOCK level
  rules: [
    { minTrust: 0, tools: ['get_*'] },
    { minTrust: 30, tools: ['write_*'] },
  ],
  audit: true,
});
```

When an agent with abuse reports tries to call a tool:
```
[mcp-guard] DENY bad-agent → write_file (score: -1, band: ABUSE_REPORTED)
  agent reported in KYA abuse database: prompt_injection (1 reports, severity: high)
```

Report abuse: `POST https://agentscores.xyz/api/abuse/report`
Check an agent: `GET https://agentscores.xyz/api/abuse/check?agent=name`

For standalone abuse checking without the full middleware, use [kya-abuse-check](https://www.npmjs.com/package/kya-abuse-check).

## Part of KYA (Know Your Agent)

mcp-trust-guard is the server-side component of [KYA](https://agentscores.xyz) — real-time AI agent verification. Six checks: Deployer, Model, Code, Abuse, Permissions, Deployment. No platform registration required.

## License

MIT
