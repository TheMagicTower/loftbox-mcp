/** OAuth 인가코드 브로커 — Claude/ChatGPT 웹 클라이언트용.
 *
 * 기존 LoftBox API 키를 브라우저에서 승인받아 opaque MCP OAuth 토큰을
 * 발급하는 fail-closed 브로커다. 핵심 분리:
 * - Claude/ChatGPT 에는 opaque 토큰(`lbmcp_at_…`)만 전달된다.
 * - 원본 API 키는 암호화되어 이 서버에만 보관되고, 다운스트림 호출 시
 *   서버 어댑터 안에서만 복호화된다. OAuth 토큰을 LoftBox API 로 절대
 *   전달하지 않는다(MCP 인증 스펙 2025-11-25).
 * - 키 발급·scope 변경은 하지 않는다. 승인 시 GET /v1/auth/context 로
 *   기존 키를 검증하고 조직/키 컨텍스트에 grant 를 바인딩한다.
 *   기존 로그인 세션(SSO)이 아니다.
 *
 * 단일 프로세스 전제. 재시작하면 메모리 상태(트랜잭션·코드·액세스 토큰)는
 * 사라지고, durable 저장소의 클라이언트·grant·리프레시 토큰은 유지된다.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import {
  ACCESS_TOKEN_PREFIX,
  KEY_VALIDATION_TIMEOUT_MS,
  MAX_ACCESS_TOKENS,
  MAX_API_KEY_CHARS,
  MAX_CLIENT_NAME_CHARS,
  MAX_CODES,
  MAX_FORM_BYTES,
  MAX_DCR_BODY_BYTES,
  MAX_QUERY_CHARS,
  MAX_RATE_IPS,
  MAX_REDIRECT_URIS,
  MAX_SCOPE_CHARS,
  MAX_STATE_CHARS,
  MAX_TOKEN_FORM_BYTES,
  MAX_TXN_ATTEMPTS,
  MAX_TXNS,
  MAX_URI_CHARS,
  OAUTH_SCOPE_MANAGE,
  OAUTH_SCOPE_READ,
  RATE_LIMIT_MAX,
  RATE_LIMIT_WINDOW_MS,
  REFRESH_TOKEN_PREFIX,
  effectiveScopes,
  isLoopbackHostname,
  isNonNilUuid,
  isValidChallenge,
  isValidVerifier,
  normalizeIp,
  parseScopeParam,
  rightmostForwardedIp,
  validateRedirectUri,
  type OAuthConfig,
} from "./oauth-config.js";
import {
  decryptSecret,
  encryptSecret,
  FileOAuthStore,
  isStoreCapacityError,
  sha256Hex,
  type StoreData,
} from "./oauth-store.js";
import {
  escapeHtml,
  renderAuthorizePage,
  renderErrorPage,
} from "./oauth-html.js";

/* ─── 내부 레코드 ─────────────────────────────────────────────── */

interface Txn {
  id: string;
  csrfHash: string;
  cookieHash: string;
  client_id: string;
  client_name: string | null;
  redirect_uri: string;
  resource: string;
  scope: string[];
  /** 클라이언트가 보낸 state 그대로(null=미제공). POST 교체 불가. */
  state: string | null;
  challenge: string;
  created_at: number;
  expires_at: number;
  attempts: number;
  consumed: boolean;
  /** 키 검증 await 전 동기 claim — 동시 이중 제출 시 단일 grant 보장. */
  claimed: boolean;
}

interface Code {
  client_id: string;
  redirect_uri: string;
  resource: string;
  challenge: string;
  scope: string[];
  grant_id: string;
  expires_at: number;
}

interface Access {
  grant_id: string;
  client_id: string;
  scope: string[];
  expires_at: number;
}

export interface AuthContext {
  ok: boolean;
  status: number;
  org_id: string | null;
  org_slug: string | null;
  org_name: string | null;
  key_id: string | null;
  granted_scopes: string[];
  effective_scopes: string[];
}

/** 키 검증 함수 — 기본 구현은 env 의 LOFTBOX_BASE_URL 로 호출. */
export type ValidateKeyFn = (apiKey: string) => Promise<AuthContext>;

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function strArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((s): s is string => typeof s === "string").slice(0, 128);
}

function defaultBaseUrl(): string {
  return process.env.LOFTBOX_BASE_URL ?? "https://api.loftbox.net";
}

/** GET /v1/auth/context 로 기존 키를 검증한다(읽기 전용 호출).
 *  문서화된 정확한 형태만 인정한다 —
 *  organization{id,name,slug} + api_key_id + granted/effective_scopes.
 *  dev/세션 폴백(b.org_id/b.key_id 등)은 절대 인정하지 않는다. */
export async function validateKeyWithApi(apiKey: string): Promise<AuthContext> {
  const failed = (status: number): AuthContext => ({
    ok: false,
    status,
    org_id: null,
    org_slug: null,
    org_name: null,
    key_id: null,
    granted_scopes: [],
    effective_scopes: [],
  });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), KEY_VALIDATION_TIMEOUT_MS);
  try {
    const res = await fetch(
      `${defaultBaseUrl().replace(/\/+$/, "")}/v1/auth/context`,
      {
        headers: { Authorization: `Bearer ${apiKey}` },
        signal: controller.signal,
        // Authorization 이 Location 목적지로 따라가지 않게 수동 처리.
        redirect: "manual",
      },
    );
    // 모든 3xx 는 리다이렉트를 절대 따라가지 않고 502 실패로 취급한다 —
    // same-origin 포함, Location 목적지에 요청을 보내지 않는다.
    if (res.status >= 300 && res.status <= 399) return failed(502);
    if (res.status === 401 || res.status === 403) return failed(res.status);
    if (!res.ok) return failed(res.status);
    let body: unknown;
    try {
      body = JSON.parse(await res.text());
    } catch {
      return failed(502);
    }
    if (!body || typeof body !== "object") return failed(502);
    const b = body as Record<string, unknown>;
    const org =
      b.organization && typeof b.organization === "object"
        ? (b.organization as Record<string, unknown>)
        : {};
    return {
      ok: true,
      status: 200,
      org_id: str(org.id),
      org_slug: str(org.slug),
      org_name: str(org.name),
      key_id: str(b.api_key_id),
      granted_scopes: strArray(b.granted_scopes),
      effective_scopes: strArray(b.effective_scopes),
    };
  } catch {
    return failed(0);
  } finally {
    clearTimeout(timer);
  }
}

/* ─── 작은 헬퍼 ───────────────────────────────────────────────── */

function b64url(n: number): string {
  return randomBytes(n).toString("base64url");
}

function hashEquals(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a, "utf8").digest();
  const hb = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(ha, hb);
}

function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  extra: Record<string, string> = {},
): void {
  res.writeHead(status, {
    "content-type": "application/json",
    "x-content-type-options": "nosniff",
    ...extra,
  });
  res.end(JSON.stringify(body));
}

function sendHtml(
  res: ServerResponse,
  status: number,
  html: string,
  opts: { referrerPolicy?: string; csp?: string } = {},
): void {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
    "referrer-policy": opts.referrerPolicy ?? "no-referrer",
    "content-security-policy":
      opts.csp ??
      "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; " +
        "form-action 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
  });
  res.end(html);
}

/** RFC6749 토큰 오류 JSON (no-store). 비밀 미포함. */
function tokenError(
  res: ServerResponse,
  status: number,
  error: string,
  description?: string,
): void {
  sendJson(
    res,
    status,
    description ? { error, error_description: description } : { error },
    { "cache-control": "no-store", pragma: "no-cache" },
  );
}

async function readBounded(
  req: IncomingMessage,
  maxBytes: number,
): Promise<Buffer | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > maxBytes) return null;
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

function isForm(req: IncomingMessage): boolean {
  const ct = req.headers["content-type"] ?? "";
  return (
    ct.split(";")[0]!.trim().toLowerCase() ===
    "application/x-www-form-urlencoded"
  );
}

function isJson(req: IncomingMessage): boolean {
  const ct = req.headers["content-type"] ?? "";
  return ct.split(";")[0]!.trim().toLowerCase() === "application/json";
}

/** 같은 이름의 OAuth 파라미터가 2개 이상이면 true(모호성 거부용). */
function hasDuplicates(params: URLSearchParams, names: string[]): boolean {
  return names.some((n) => params.getAll(n).length > 1);
}

function parseCookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(";").slice(0, 32)) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part
      .slice(idx + 1)
      .trim()
      .slice(0, 1024);
    if (k) out[k] = v.startsWith('"') ? v.slice(1, -1) : v;
  }
  return out;
}

/** 등록된 redirect_uri 에 파라미터를 추가한다(기존 쿼리 유지). */
function appendRedirectParams(
  redirectUri: string,
  params: Record<string, string>,
): string | null {
  try {
    const u = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) u.searchParams.append(k, v);
    return u.toString();
  } catch {
    return null;
  }
}

function callbackHostOf(uri: string): string {
  try {
    return new URL(uri).host;
  } catch {
    return "(알 수 없음)";
  }
}

/** CSP form-action 에 허용할 콜백 origin — 검증된 등록 URI에서만
 *  구성하며, 형태가 아니면 null(→ 'self'만). 와일드카드·주입 불가. */
function callbackOriginForCsp(uri: string): string | null {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  if (u.username || u.password) return null;
  const origin = `${u.protocol}//${u.host}`;
  if (!/^[a-z]+:\/\/[A-Za-z0-9.\-:\[\]]+$/.test(origin)) return null;
  return origin;
}

/** 동의 페이지·콜백 리다이렉트용 CSP. 폼 POST 후 302 로 외국
 *  콜백으로 이동할 때 Chrome form-action 차단을 피하려 등록된
 *  콜백 origin 하나만 추가한다(와일드카드 없음). */
function cspForCallback(uri: string): string {
  const extra = callbackOriginForCsp(uri);
  const fa = extra ? `form-action 'self' ${extra}` : "form-action 'self'";
  return (
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; " +
    `${fa}; frame-ancestors 'none'`
  );
}

/* ─── DCR 스키마 ──────────────────────────────────────────────── */

const DcrSchema = z.object({
  redirect_uris: z
    .array(z.string().max(MAX_URI_CHARS))
    .min(1)
    .max(MAX_REDIRECT_URIS),
  client_name: z.string().min(1).max(MAX_CLIENT_NAME_CHARS).optional(),
  token_endpoint_auth_method: z.literal("none").optional(),
  grant_types: z.array(z.string().max(64)).max(8).optional(),
  response_types: z.array(z.string().max(32)).max(8).optional(),
  scope: z.string().max(MAX_SCOPE_CHARS).optional(),
});

const TXN_COOKIE = "lbmcp_txn";

export interface AccessCheck {
  apiKey: string;
  grant_id: string;
  client_id: string;
  scope: string[];
  scopeKey: string;
  /** 디스패치 경계 동기 가드용 원본 정체성(만료·조직/키 바인딩). */
  expires_at: number;
  org_id: string;
  key_id: string;
}

export type AccessResult =
  | { ok: true; check: AccessCheck }
  | { ok: false; kind: "invalid_token" | "upstream" };

/** 리프레시 원자 판정 결과 — 단일 저장소 트랜잭션 안에서 결정된다. */
type RefreshOutcome =
  | {
      ok: true;
      grant_id: string;
      client_id: string;
      scope: string[];
      next: string;
    }
  | {
      ok: false;
      error: string;
      description: string;
      /** 재사용으로 계열 폐기된 grant — 메모리 정리용. */
      revokedGrant?: string;
    };

function refreshFail(
  error: string,
  description: string,
  revokedGrant?: string,
): RefreshOutcome {
  return { ok: false, error, description, revokedGrant };
}

/** 리프레시 검증·회전·재사용판정을 하나의 저장소 트랜잭션에서 수행한다.
 *  호출자는 성공 시에만(커밋 후) 액세스 토큰을 발급·응답한다. */
function decideRefresh(
  d: StoreData,
  args: {
    h: string;
    client_id: string;
    wantScope: string[] | null;
    now: number;
    origin: string;
    resource: string;
    refreshTtlSecs: number;
  },
): RefreshOutcome {
  const { h, client_id, wantScope, now, origin, resource, refreshTtlSecs } =
    args;
  // 등록된 정확한 client_id 필수 — 소유권 검사가 재사용 판단보다 먼저다.
  // 타 클라이언트의 리플레이 시도가 피해 grant 를 폐기하지 않게 한다.
  if (!d.clients[client_id]) {
    return refreshFail("invalid_client", "등록되지 않은 클라이언트");
  }
  const rec = d.refresh[h] ?? null;
  if (!rec) {
    return refreshFail("invalid_grant", "토큰이 유효하지 않습니다");
  }
  if (rec.client_id !== client_id) {
    return refreshFail("invalid_grant", "클라이언트 불일치");
  }
  if (rec.issuer !== origin || rec.resource !== resource) {
    return refreshFail("invalid_grant", "토큰 바인딩 불일치");
  }
  const grant = d.grants[rec.grant_id] ?? null;
  if (!grant || grant.revoked_at !== null) {
    delete d.refresh[h];
    return refreshFail("invalid_grant", "grant 무효");
  }
  if (grant.client_id !== client_id) {
    delete d.refresh[h];
    return refreshFail("invalid_grant", "grant 바인딩 불일치");
  }
  if (grant.issuer !== origin || grant.resource !== resource) {
    return refreshFail("invalid_grant", "grant 바인딩 불일치");
  }
  if (rec.expires_at <= now) {
    delete d.refresh[h];
    return refreshFail("invalid_grant", "토큰이 만료되었습니다");
  }
  // 회전된 토큰 재사용 = 탈취 의심 → 같은 트랜잭션에서 grant 전체 폐기.
  if (rec.consumed_at !== null) {
    grant.revoked_at = now;
    for (const [key, r] of Object.entries(d.refresh)) {
      if (r.grant_id === grant.grant_id) delete d.refresh[key];
    }
    return refreshFail(
      "invalid_grant",
      "토큰이 유효하지 않습니다",
      grant.grant_id,
    );
  }
  // manage 는 read 를 내포 — 구버전 manage 단독 저장분과 정규화된
  // wantScope(manage→read+manage)의 부분집합 검사를 프로필 의미로 수행.
  const recEffective = effectiveScopes(rec.scope);
  if (wantScope && !wantScope.every((s) => recEffective.includes(s))) {
    return refreshFail("invalid_scope", "승인 범위를 초과합니다");
  }
  const scope = effectiveScopes(wantScope ?? rec.scope)
    .slice()
    .sort();
  const next = `${REFRESH_TOKEN_PREFIX}${b64url(32)}`;
  rec.consumed_at = now;
  d.refresh[sha256Hex(next)] = {
    grant_id: grant.grant_id,
    client_id: grant.client_id,
    scope,
    issuer: origin,
    resource,
    created_at: now,
    expires_at: now + refreshTtlSecs * 1000,
    consumed_at: null,
  };
  return { ok: true, grant_id: grant.grant_id, client_id, scope, next };
}

/** OAuth 브로커 — 서버 인스턴스당 하나(메모리 상태 격리). */
export class OAuthBroker {
  readonly config: OAuthConfig;
  readonly store: FileOAuthStore;
  private readonly validateKey: ValidateKeyFn;
  private readonly txns = new Map<string, Txn>();
  private readonly codes = new Map<string, Code>();
  private readonly access = new Map<string, Access>();
  private readonly rate = new Map<string, { count: number; reset: number }>();
  /** 리프레시 read-then-mutate 직렬화(동시 재사용 방지). */
  private refreshChain: Promise<void> = Promise.resolve();

  constructor(
    config: OAuthConfig,
    store: FileOAuthStore,
    validateKey: ValidateKeyFn = validateKeyWithApi,
  ) {
    this.config = config;
    this.store = store;
    this.validateKey = validateKey;
  }

  /* ─── 가드 ─────────────────────────────────────────────── */

  /** OAuth 전용 속도 제한 버킷 키. 실제 소켓 피어가 명시적 신뢰
   *  프록시 목록에 있을 때만 X-Forwarded-For 우측 IP 를 쓰고, 그 외에는
   *  항상 실제 소켓 피어로 버킷한다. 헤더 존재·루프백만으로는 절대
   *  신뢰하지 않는다. host/origin/issuer/auth/context/MCP 판정과 무관. */
  private rateBucketKey(req: IncomingMessage): string {
    const socketRaw = req.socket.remoteAddress ?? "unknown";
    const socketIp = normalizeIp(socketRaw);
    const socketKey = socketIp ?? socketRaw.slice(0, 128);
    if (socketIp !== null && this.config.trustedProxyIps.includes(socketIp)) {
      const fwd = rightmostForwardedIp(req.headers["x-forwarded-for"]);
      if (fwd !== null) return fwd;
    }
    return socketKey;
  }

  /** 베스트 에포트 IP 속도 제한. 초과 시 false. */
  checkRate(req: IncomingMessage): boolean {
    const ip = this.rateBucketKey(req);
    const now = Date.now();
    const cur = this.rate.get(ip);
    if (!cur || cur.reset <= now) {
      this.rate.set(ip, { count: 1, reset: now + RATE_LIMIT_WINDOW_MS });
    } else {
      cur.count += 1;
      if (cur.count > RATE_LIMIT_MAX) return false;
    }
    if (this.rate.size > MAX_RATE_IPS) {
      // 오래된 항목부터 정리한다(삽입 순서).
      for (const k of this.rate.keys()) {
        this.rate.delete(k);
        if (this.rate.size <= MAX_RATE_IPS) break;
      }
    }
    return true;
  }

  /** 요청 Host 가 신뢰 origin(또는 테스트 루프백)과 일치하는지.
   *  /oauth/* 와 /mcp 인증 요청에 모두 적용된다. */
  hostOk(req: IncomingMessage): boolean {
    const host = req.headers.host;
    if (!host) return false;
    if (!this.config.allowInsecureLoopback) {
      const expected = new URL(this.config.publicOrigin).host.toLowerCase();
      return host.toLowerCase() === expected;
    }
    return isLoopbackHostname(hostnameOf(host));
  }

  /** authorize POST 의 Origin 이 신뢰 origin(또는 테스트 루프백)인지. */
  private trustedPostOrigin(origin: string | undefined): boolean {
    if (!origin) return false;
    if (!this.config.allowInsecureLoopback)
      return origin === this.config.publicOrigin;
    let u: URL;
    try {
      u = new URL(origin);
    } catch {
      return false;
    }
    if (u.username || u.password) return false;
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    if (u.pathname !== "/" && u.pathname !== "") return false;
    if (u.search || u.hash) return false;
    return isLoopbackHostname(u.hostname);
  }

  /** /mcp 요청의 Origin 검사 — 없으면 통과(서버간 호출), 있으면 신뢰값만. */
  mcpOriginOk(req: IncomingMessage): boolean {
    const origin = req.headers.origin;
    if (origin === undefined) return true;
    if (!this.config.allowInsecureLoopback) {
      return origin === this.config.publicOrigin;
    }
    if (origin === this.config.publicOrigin) return true;
    return this.trustedPostOrigin(origin);
  }

  /* ─── 메타데이터 ───────────────────────────────────────── */

  protectedResourceDoc(): Record<string, unknown> {
    return {
      resource: this.config.resource,
      authorization_servers: [this.config.publicOrigin],
      scopes_supported: [OAUTH_SCOPE_READ, OAUTH_SCOPE_MANAGE],
      bearer_methods_supported: ["header"],
      resource_name: "LoftBox MCP",
      resource_documentation: `${this.config.publicOrigin}/setup`,
    };
  }

  authServerDoc(): Record<string, unknown> {
    const o = this.config.publicOrigin;
    return {
      issuer: o,
      authorization_endpoint: `${o}/oauth/authorize`,
      token_endpoint: `${o}/oauth/token`,
      registration_endpoint: `${o}/oauth/register`,
      revocation_endpoint: `${o}/oauth/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [OAUTH_SCOPE_READ, OAUTH_SCOPE_MANAGE],
      authorization_response_iss_parameter_supported: true,
    };
  }

  handleMetadata(res: ServerResponse): void {
    sendJson(res, 200, this.protectedResourceDoc(), {
      "cache-control": "public, max-age=3600",
    });
  }

  handleAuthServerMetadata(res: ServerResponse): void {
    sendJson(res, 200, this.authServerDoc(), {
      "cache-control": "public, max-age=3600",
    });
  }

  wwwAuthenticate(): string {
    return (
      `Bearer realm="loftbox-mcp", ` +
      `resource_metadata="${this.config.publicOrigin}/.well-known/oauth-protected-resource", ` +
      `scope="${OAUTH_SCOPE_READ} ${OAUTH_SCOPE_MANAGE}"`
    );
  }

  /* ─── DCR (공개 클라이언트 등록) ─────────────────────────── */

  async handleRegister(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    if (!isJson(req)) {
      tokenError(res, 400, "invalid_client_metadata", "JSON 본문이 필요합니다");
      return;
    }
    const raw = await readBounded(req, MAX_DCR_BODY_BYTES);
    if (raw === null) {
      tokenError(res, 400, "invalid_client_metadata", "본문이 너무 큽니다");
      return;
    }
    let doc: unknown;
    try {
      doc = JSON.parse(raw.toString("utf8"));
    } catch {
      tokenError(res, 400, "invalid_client_metadata", "잘못된 JSON");
      return;
    }
    const parsed = DcrSchema.safeParse(doc);
    if (!parsed.success) {
      tokenError(res, 400, "invalid_client_metadata", "메타데이터 검증 실패");
      return;
    }
    const body = parsed.data;
    // grant/response 타입은 인가코드 흐름만 허용한다.
    if (body.grant_types) {
      const allowed = new Set(["authorization_code", "refresh_token"]);
      if (!body.grant_types.every((g) => allowed.has(g))) {
        tokenError(res, 400, "invalid_client_metadata", "grant_types 미지원");
        return;
      }
    }
    if (
      body.response_types &&
      !body.response_types.every((r) => r === "code")
    ) {
      tokenError(res, 400, "invalid_client_metadata", "response_types 미지원");
      return;
    }
    if (body.scope) {
      const scopes = parseScopeParam(body.scope);
      if (!scopes.ok) {
        tokenError(res, 400, "invalid_client_metadata", "scope 미지원");
        return;
      }
    }
    const uris: string[] = [];
    for (const candidate of body.redirect_uris) {
      const v = validateRedirectUri(
        candidate,
        this.config.allowInsecureLoopback,
      );
      if (!v.ok) {
        tokenError(res, 400, "invalid_redirect_uri", v.reason);
        return;
      }
      uris.push(v.uri);
    }
    const uniqueUris = [...new Set(uris)];
    const count = this.store.read((d) => Object.keys(d.clients).length);
    if (count >= 2000) {
      tokenError(res, 503, "temporarily_unavailable", "등록 한도 초과");
      return;
    }
    const client_id = `lbmcp_cli_${b64url(16)}`;
    const client_name = body.client_name?.trim() || null;
    try {
      await this.store.mutate((d) => {
        d.clients[client_id] = {
          client_id,
          client_name,
          redirect_uris: uniqueUris,
          created_at: Date.now(),
        };
      });
    } catch (e) {
      // 용량 초과는 안전 503 — 저장소 변경 없이 롤백되며 브로커를 오염시키지
      // 않는다. 기존 grant 는 계속 동작한다.
      if (isStoreCapacityError(e)) {
        tokenError(res, 503, "temporarily_unavailable", "등록 한도 초과");
        return;
      }
      tokenError(res, 500, "server_error", "일시적인 오류입니다");
      return;
    }
    sendJson(
      res,
      201,
      {
        client_id,
        ...(client_name ? { client_name } : {}),
        redirect_uris: uniqueUris,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      },
      { "cache-control": "no-store" },
    );
  }

  /* ─── 인가(브라우저 승인) ────────────────────────────────── */

  /** 유효한 client+redirect 로의 오류 리다이렉트(RFC9207 iss 포함).
   *  state 는 제공된 값을 정확히(빈 값 포함) 반환하고, 중복·초과분은
   *  미반사한다. 폼 POST 뒤 리다이렉트의 Chrome form-action 검사를
   *  위해 등록 콜백 origin 을 CSP 에 포함한다. */
  private redirectError(
    res: ServerResponse,
    redirectUri: string,
    state: string | null,
    error: string,
    description: string,
  ): void {
    const params: Record<string, string> = {
      error,
      error_description: description,
      iss: this.config.publicOrigin,
    };
    if (state !== null && state !== undefined) params.state = state;
    const location = appendRedirectParams(redirectUri, params);
    if (!location) {
      sendHtml(
        res,
        400,
        renderErrorPage("연결 오류", "콜백 주소가 올바르지 않습니다."),
      );
      return;
    }
    res.writeHead(302, {
      location,
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "content-security-policy": cspForCallback(redirectUri),
    });
    res.end();
  }

  private txnCookie(id: string, secret: string, maxAge: number): string {
    const parts = [
      `${TXN_COOKIE}=${id}.${secret}`,
      "HttpOnly",
      "SameSite=Lax",
      "Path=/oauth/authorize",
      `Max-Age=${maxAge}`,
    ];
    if (new URL(this.config.publicOrigin).protocol === "https:") {
      parts.push("Secure");
    }
    return parts.join("; ");
  }

  private clearTxnCookie(): string {
    const parts = [
      `${TXN_COOKIE}=;`,
      "HttpOnly",
      "SameSite=Lax",
      "Path=/oauth/authorize",
      "Max-Age=0",
    ];
    if (new URL(this.config.publicOrigin).protocol === "https:") {
      parts.push("Secure");
    }
    return parts.join("; ");
  }

  private pruneMemory(): void {
    const now = Date.now();
    for (const [k, t] of this.txns) {
      if (t.consumed || t.expires_at <= now) this.txns.delete(k);
    }
    for (const [k, c] of this.codes) {
      if (c.expires_at <= now) this.codes.delete(k);
    }
    for (const [k, a] of this.access) {
      if (a.expires_at <= now) this.access.delete(k);
    }
    trimMap(this.txns, MAX_TXNS);
    trimMap(this.codes, MAX_CODES);
    trimMap(this.access, MAX_ACCESS_TOKENS);
  }

  async handleAuthorizeGet(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const url = req.url ?? "";
    if (url.length > MAX_QUERY_CHARS + 256) {
      sendHtml(res, 414, renderErrorPage("요청 초과", "요청이 너무 깁니다."));
      return;
    }
    const q = new URL(url, "http://local").searchParams;
    const client_id = (q.get("client_id") ?? "").slice(0, 256);
    const redirect_uri = (q.get("redirect_uri") ?? "").slice(
      0,
      MAX_URI_CHARS + 1,
    );
    const rawState = q.get("state");
    const stateDup = q.getAll("state").length > 1;
    const stateOversized =
      rawState !== null && rawState.length > MAX_STATE_CHARS;
    // 리다이렉트에 사용해도 안전한 state — 중복·초과분은 미반사한다.
    const safeState = stateDup || stateOversized ? null : rawState;
    const page = (msg: string): void => {
      sendHtml(res, 400, renderErrorPage("연결 요청 오류", msg));
    };

    // client/redirect 자체가 중복이면 콜백을 신뢰할 수 없어 페이지 오류.
    if (hasDuplicates(q, ["client_id", "redirect_uri"])) {
      page("중복된 요청 파라미터가 있습니다.");
      return;
    }
    // client+redirect 가 유효할 때만 리다이렉트 오류를 사용한다.
    const client = client_id
      ? this.store.read((d) => d.clients[client_id] ?? null)
      : null;
    const redirectValid =
      !!client && !!redirect_uri && client.redirect_uris.includes(redirect_uri);
    const redir = (error: string, description: string): void => {
      if (client && redirectValid) {
        this.redirectError(res, redirect_uri, safeState, error, description);
      } else {
        page(description);
      }
    };

    if (!client || !redirectValid) {
      page(
        "등록되지 않은 클라이언트이거나 콜백 주소가 일치하지 않습니다. " +
          "클라이언트 설정에서 다시 등록해 주세요. (이 오류는 콜백으로 이동하지 않습니다.)",
      );
      return;
    }
    if (
      hasDuplicates(q, [
        "response_type",
        "resource",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
      ])
    ) {
      redir("invalid_request", "중복된 요청 파라미터가 있습니다");
      return;
    }
    if (stateOversized) {
      redir("invalid_request", "state 가 너무 깁니다");
      return;
    }
    const resource = q.get("resource");
    if (resource !== this.config.resource) {
      redir("invalid_target", "resource 가 MCP 서버와 일치해야 합니다");
      return;
    }
    if (q.get("response_type") !== "code") {
      redir("unsupported_response_type", "response_type=code 만 지원합니다");
      return;
    }
    const scopes = parseScopeParam(q.get("scope"));
    if (!scopes.ok) {
      redir("invalid_scope", scopes.reason);
      return;
    }
    // state 는 선택이다 — 제공되면(빈 값 포함) 정확히 roundtrip 한다.
    // 표준 SDK 클라이언트의 state 훅은 선택이며, PKCE 와 브라우저 바인딩
    // 동의가 별도 보호를 제공한다.
    const challenge = q.get("code_challenge") ?? "";
    const method = q.get("code_challenge_method");
    if (method !== "S256" || !isValidChallenge(challenge)) {
      redir("invalid_request", "PKCE S256 code_challenge 이 필요합니다");
      return;
    }

    this.pruneMemory();
    const now = Date.now();
    const csrfToken = b64url(32);
    const cookieSecret = b64url(32);
    const txn: Txn = {
      id: b64url(16),
      csrfHash: sha256Hex(csrfToken),
      cookieHash: sha256Hex(cookieSecret),
      client_id: client.client_id,
      client_name: client.client_name,
      redirect_uri,
      resource: this.config.resource,
      scope: scopes.scopes,
      state: rawState,
      challenge,
      created_at: now,
      expires_at: now + this.config.txnTtlSecs * 1000,
      attempts: 0,
      consumed: false,
      claimed: false,
    };
    // CSRF 토큰은 폼 hidden 필드로, 쿠키 비밀은 HttpOnly 쿠키로 분리한다.
    this.txns.set(txn.id, txn);
    res.setHeader(
      "set-cookie",
      this.txnCookie(txn.id, cookieSecret, this.config.txnTtlSecs),
    );
    // 동의 페이지는 same-origin referrer 정책을 쓴다 — no-referrer 는
    // Chromium 이 same-origin 폼 POST 에 Origin:null 을 보내게 해서
    // 정상 브라우저 제출이 Origin 검사에 걸린다. 교차 출처 유출 방지는
    // 유지된다. 콜백 리다이렉트에는 no-referrer 를 유지한다.
    sendHtml(
      res,
      200,
      renderAuthorizePage({
        txnId: txn.id,
        csrfToken,
        clientName: client.client_name,
        clientId: client.client_id,
        callbackHost: callbackHostOf(redirect_uri),
        callbackUri: redirect_uri,
        requestedManage: scopes.scopes.includes(OAUTH_SCOPE_MANAGE),
        orgHint: null,
        error: null,
        manageChecked: false,
      }),
      {
        referrerPolicy: "same-origin",
        csp: cspForCallback(redirect_uri),
      },
    );
  }

  async handleAuthorizePost(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const page = (status: number, msg: string): void => {
      sendHtml(res, status, renderErrorPage("승인 처리 오류", msg));
    };
    if (!isForm(req)) {
      page(400, "폼 요청이 아닙니다.");
      return;
    }
    // 동일 신뢰 Origin 에서 온 브라우저 제출만 받는다(CSRF).
    // Origin:null 은 절대 받지 않는다.
    if (!this.trustedPostOrigin(req.headers.origin)) {
      page(
        403,
        "요청 출처(Origin) 검증에 실패했습니다. 승인 페이지를 새로 열어 다시 시도하세요.",
      );
      return;
    }
    const raw = await readBounded(req, MAX_FORM_BYTES);
    if (raw === null) {
      page(413, "요청 본문이 너무 큽니다.");
      return;
    }
    const form = new URLSearchParams(raw.toString("utf8"));
    if (
      hasDuplicates(form, [
        "txn",
        "csrf",
        "decision",
        "api_key",
        "allow_manage",
      ])
    ) {
      page(400, "중복된 폼 항목이 있습니다.");
      return;
    }
    const txnId = (form.get("txn") ?? "").slice(0, 256);
    const csrf = (form.get("csrf") ?? "").slice(0, 256);
    const txn = this.txns.get(txnId) ?? null;

    // 트랜잭션+쿠키+CSRF 삼중 바인딩(일회용·단명).
    // 폼의 state 항목이 있어도 무시한다 — 저장된 state 를 교체할 수 없다.
    if (!txn || txn.consumed || txn.expires_at <= Date.now()) {
      if (txn) this.txns.delete(txnId);
      res.setHeader("set-cookie", this.clearTxnCookie());
      page(
        400,
        "승인 요청이 만료되었거나 이미 처리되었습니다(서버 재시작 포함). " +
          "클라이언트 설정에서 연결을 다시 시작하세요.",
      );
      return;
    }
    const cookieRaw = parseCookies(req)[TXN_COOKIE] ?? "";
    const dot = cookieRaw.indexOf(".");
    const cookieId = dot > 0 ? cookieRaw.slice(0, dot) : "";
    const cookieSecret = dot > 0 ? cookieRaw.slice(dot + 1) : "";
    if (
      cookieId !== txn.id ||
      !cookieSecret ||
      !hashEquals(sha256Hex(cookieSecret), txn.cookieHash)
    ) {
      page(
        403,
        "브라우저 세션 검증에 실패했습니다. 승인 페이지를 새로 열어 다시 시도하세요.",
      );
      return;
    }
    if (!csrf || !hashEquals(sha256Hex(csrf), txn.csrfHash)) {
      page(
        403,
        "CSRF 검증에 실패했습니다. 승인 페이지를 새로 열어 다시 시도하세요.",
      );
      return;
    }
    // 동시 이중 제출 가드 — 아래 allow 경로는 키 검증 await 전에
    // claim 을 잡아 하나의 grant/코드만 만든다.
    if (txn.claimed) {
      page(400, "이미 처리 중인 승인 요청입니다. 잠시 후 결과를 확인하세요.");
      return;
    }

    const renderRetry = (error: string, manageChecked: boolean): void => {
      // 재시도: 키는 절대 다시 채우지 않는다(HTML 무반사).
      // claim 을 풀어 정상적인 무효 키 재입력을 허용한다.
      txn.claimed = false;
      sendHtml(
        res,
        200,
        renderAuthorizePage({
          txnId: txn.id,
          csrfToken: csrf,
          clientName: txn.client_name,
          clientId: txn.client_id,
          callbackHost: callbackHostOf(txn.redirect_uri),
          callbackUri: txn.redirect_uri,
          requestedManage: txn.scope.includes(OAUTH_SCOPE_MANAGE),
          orgHint: null,
          error,
          manageChecked,
        }),
        {
          referrerPolicy: "same-origin",
          csp: cspForCallback(txn.redirect_uri),
        },
      );
    };

    const decision = form.get("decision");
    if (decision === "deny") {
      txn.consumed = true;
      this.txns.delete(txn.id);
      res.setHeader("set-cookie", this.clearTxnCookie());
      this.redirectError(
        res,
        txn.redirect_uri,
        txn.state,
        "access_denied",
        "사용자가 거부했습니다",
      );
      return;
    }
    if (decision !== "allow") {
      page(400, "승인 여부가 올바르지 않습니다.");
      return;
    }

    // 키 검증 await 전에 동기 claim — 동시 제출은 위에서 400 이 된다.
    txn.claimed = true;
    txn.attempts += 1;
    if (txn.attempts > MAX_TXN_ATTEMPTS) {
      txn.consumed = true;
      this.txns.delete(txn.id);
      res.setHeader("set-cookie", this.clearTxnCookie());
      page(
        429,
        "시도 횟수를 초과했습니다. 클라이언트에서 연결을 다시 시작하세요.",
      );
      return;
    }

    const manageChecked = form.get("allow_manage") === "yes";
    const apiKey = (form.get("api_key") ?? "").trim();
    if (!apiKey || apiKey.length > MAX_API_KEY_CHARS) {
      renderRetry("API 키를 입력하세요.", manageChecked);
      return;
    }

    // 기존 키 검증 — 읽기 전용 auth/context 호출.
    let ctx: AuthContext;
    try {
      ctx = await this.validateKey(apiKey);
    } catch {
      renderRetry(
        "검증 중 오류가 발생했습니다. 잠시 후 다시 시도하세요.",
        manageChecked,
      );
      return;
    }
    // await 사이 동시 결정을 다시 확인한다(방어적 재검증).
    if (txn.consumed || this.txns.get(txn.id) !== txn) {
      res.setHeader("set-cookie", this.clearTxnCookie());
      page(
        400,
        "승인 요청이 이미 처리되었습니다. 클라이언트에서 다시 시작하세요.",
      );
      return;
    }
    if (!ctx.ok && (ctx.status === 401 || ctx.status === 403)) {
      renderRetry(
        "API 키가 유효하지 않습니다. 기존에 발급받은 키인지 확인하고 다시 입력하세요.",
        manageChecked,
      );
      return;
    }
    if (!ctx.ok) {
      renderRetry(
        "LoftBox API 에 연결할 수 없습니다. 잠시 후 다시 시도하세요.",
        manageChecked,
      );
      return;
    }
    // 브라우저 승인은 non-nil UUID 조직/키 바인딩 필수 —
    // null·비정형(dev/세션) 컨텍스트로 grant 를 만들지 않는다.
    if (!isNonNilUuid(ctx.org_id) || !isNonNilUuid(ctx.key_id)) {
      renderRetry(
        "이 키는 브라우저 승인에 사용할 수 없습니다(조직·키 식별자 확인 불가). " +
          "기존에 발급받은 API 키인지 확인하고 다시 입력하세요.",
        manageChecked,
      );
      return;
    }

    // 승인 scope 계산: 요청 ∩ 사용자 선택. manage 는 명시적 체크 필수.
    const approved = new Set<string>([OAUTH_SCOPE_READ]);
    if (manageChecked) approved.add(OAUTH_SCOPE_MANAGE);
    const granted = txn.scope.filter((s) => approved.has(s)).sort();
    if (granted.length === 0) {
      txn.consumed = true;
      this.txns.delete(txn.id);
      res.setHeader("set-cookie", this.clearTxnCookie());
      this.redirectError(
        res,
        txn.redirect_uri,
        txn.state,
        "access_denied",
        "요청된 권한을 승인하지 않아 취소되었습니다",
      );
      return;
    }

    // grant 생성(원본 키 암호화 보관) + 인가코드 발급.
    // grant 는 발급 시점의 정확한 issuer·resource 에 바인딩된다.
    const grant_id = `lbmcp_gr_${b64url(16)}`;
    const enc = encryptSecret(this.config.encryptionKey, apiKey);
    const nowGrant = Date.now();
    try {
      await this.store.mutate((d) => {
        d.grants[grant_id] = {
          grant_id,
          client_id: txn.client_id,
          scope: granted,
          enc,
          org_id: ctx.org_id,
          org_slug: ctx.org_slug,
          org_name: ctx.org_name,
          key_id: ctx.key_id,
          backend_scopes: ctx.effective_scopes.slice(0, 128),
          issuer: this.config.publicOrigin,
          resource: this.config.resource,
          created_at: nowGrant,
          revoked_at: null,
        };
      });
    } catch (e) {
      // 영속 실패·용량 초과 — grant 없이 실패한다. claim 을 풀어 복구 후
      // 재시도할 수 있게 하고, 거짓 성공을 반환하지 않는다.
      txn.claimed = false;
      if (isStoreCapacityError(e)) {
        page(503, "저장소 용량이 가득 찼습니다. 잠시 후 다시 시도하세요.");
        return;
      }
      page(500, "일시적인 저장소 오류입니다. 잠시 후 다시 시도하세요.");
      return;
    }
    const code = `lbmcp_ac_${b64url(32)}`;
    this.codes.set(sha256Hex(code), {
      client_id: txn.client_id,
      redirect_uri: txn.redirect_uri,
      resource: txn.resource,
      challenge: txn.challenge,
      scope: granted,
      grant_id,
      expires_at: Date.now() + this.config.codeTtlSecs * 1000,
    });
    txn.consumed = true;
    this.txns.delete(txn.id);
    res.setHeader("set-cookie", this.clearTxnCookie());
    const successParams: Record<string, string> = {
      code,
      iss: this.config.publicOrigin,
    };
    if (txn.state !== null) successParams.state = txn.state;
    const location = appendRedirectParams(txn.redirect_uri, successParams);
    if (!location) {
      page(400, "콜백 주소가 올바르지 않습니다.");
      return;
    }
    res.writeHead(302, {
      location,
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "content-security-policy": cspForCallback(txn.redirect_uri),
    });
    res.end();
  }

  /* ─── 토큰 ───────────────────────────────────────────────── */

  private mintAccess(
    grant_id: string,
    client_id: string,
    scope: string[],
  ): { token: string; expires_in: number } {
    this.pruneMemory();
    const token = `${ACCESS_TOKEN_PREFIX}${b64url(32)}`;
    this.access.set(sha256Hex(token), {
      grant_id,
      client_id,
      scope: [...scope].sort(),
      expires_at: Date.now() + this.config.accessTtlSecs * 1000,
    });
    return { token, expires_in: this.config.accessTtlSecs };
  }

  async handleToken(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!isForm(req)) {
      tokenError(res, 400, "invalid_request", "폼 본문이 필요합니다");
      return;
    }
    const raw = await readBounded(req, MAX_TOKEN_FORM_BYTES);
    if (raw === null) {
      tokenError(res, 400, "invalid_request", "본문이 너무 큽니다");
      return;
    }
    const form = new URLSearchParams(raw.toString("utf8"));
    if (
      hasDuplicates(form, [
        "grant_type",
        "resource",
        "code",
        "redirect_uri",
        "client_id",
        "code_verifier",
        "refresh_token",
        "scope",
      ])
    ) {
      tokenError(res, 400, "invalid_request", "중복된 파라미터가 있습니다");
      return;
    }
    // 이 AS 는 공개 클라이언트(none) 전용 — Basic/secret 계열 인증 거부.
    if (
      req.headers.authorization !== undefined ||
      form.has("client_secret") ||
      form.has("client_assertion") ||
      form.has("client_assertion_type")
    ) {
      tokenError(
        res,
        400,
        "invalid_client",
        "공개 클라이언트 전용입니다(token_endpoint_auth_method=none)",
      );
      return;
    }
    const grant_type = form.get("grant_type") ?? "";
    // resource 는 코드교환·갱신 모두 필수이며 canonical 과 정확히 일치해야 한다.
    const resource = form.get("resource");
    if (resource !== this.config.resource) {
      tokenError(res, 400, "invalid_target", "resource 불일치");
      return;
    }
    if (grant_type === "authorization_code") {
      await this.exchangeCode(form, res);
      return;
    }
    if (grant_type === "refresh_token") {
      await this.exchangeRefresh(form, res);
      return;
    }
    tokenError(res, 400, "unsupported_grant_type", "지원하지 않는 grant");
  }

  private async exchangeCode(
    form: URLSearchParams,
    res: ServerResponse,
  ): Promise<void> {
    const code = (form.get("code") ?? "").slice(0, 512);
    const redirect_uri = (form.get("redirect_uri") ?? "").slice(
      0,
      MAX_URI_CHARS + 1,
    );
    const client_id = (form.get("client_id") ?? "").slice(0, 256);
    const verifier = (form.get("code_verifier") ?? "").slice(0, 256);
    if (!code || !redirect_uri || !client_id || !verifier) {
      tokenError(res, 400, "invalid_request", "필수 파라미터 누락");
      return;
    }
    if (!isValidVerifier(verifier)) {
      tokenError(res, 400, "invalid_grant", "verifier 형식 오류");
      return;
    }
    const h = sha256Hex(code);
    const rec = this.codes.get(h) ?? null;
    if (!rec) {
      tokenError(res, 400, "invalid_grant", "코드가 유효하지 않습니다");
      return;
    }
    // 만료·바인딩 검사 후 원자적으로 소비한다(단일 프로세스 — 동기 구간).
    if (rec.expires_at <= Date.now()) {
      this.codes.delete(h);
      tokenError(res, 400, "invalid_grant", "코드가 만료되었습니다");
      return;
    }
    if (rec.client_id !== client_id || rec.redirect_uri !== redirect_uri) {
      this.codes.delete(h);
      tokenError(res, 400, "invalid_grant", "코드 바인딩 불일치");
      return;
    }
    if (rec.resource !== this.config.resource) {
      this.codes.delete(h);
      tokenError(res, 400, "invalid_grant", "리소스 바인딩 불일치");
      return;
    }
    const expect = createHash("sha256")
      .update(verifier, "utf8")
      .digest("base64url");
    if (!hashEquals(expect, rec.challenge)) {
      this.codes.delete(h);
      tokenError(res, 400, "invalid_grant", "PKCE 검증 실패");
      return;
    }
    this.codes.delete(h);
    // grant 검증을 리프레시 생성과 같은 트랜잭션에서 — 그 사이 폐기·교체
    // 되었으면 토큰을 만들지 않는다(fail-closed).
    const scope = [...rec.scope].sort();
    const refresh = `${REFRESH_TOKEN_PREFIX}${b64url(32)}`;
    const now = Date.now();
    const origin = this.config.publicOrigin;
    const resource = this.config.resource;
    let stored = false;
    try {
      stored = await this.store.mutate((d) => {
        const grant = d.grants[rec.grant_id] ?? null;
        if (
          !grant ||
          grant.revoked_at !== null ||
          grant.client_id !== client_id ||
          grant.issuer !== origin ||
          grant.resource !== resource
        ) {
          return false;
        }
        d.refresh[sha256Hex(refresh)] = {
          grant_id: grant.grant_id,
          client_id: grant.client_id,
          scope,
          issuer: origin,
          resource,
          created_at: now,
          expires_at: now + this.config.refreshTtlSecs * 1000,
          consumed_at: null,
        };
        return true;
      });
    } catch (e) {
      // 용량 초과는 코드 복원 후 안전 503 — 재시도 가능, hidden 발급 없음.
      if (isStoreCapacityError(e)) {
        this.codes.set(h, rec);
        tokenError(res, 503, "temporarily_unavailable", "저장소 용량 초과");
        return;
      }
      tokenError(res, 500, "server_error", "일시적인 오류입니다");
      return;
    }
    if (!stored) {
      tokenError(res, 400, "invalid_grant", "grant 무효");
      return;
    }
    // 액세스 토큰은 durable 커밋 성공 후에만 발급한다.
    const grant = this.store.read((d) => d.grants[rec.grant_id] ?? null);
    if (!grant) {
      tokenError(res, 400, "invalid_grant", "grant 무효");
      return;
    }
    const access = this.mintAccess(grant.grant_id, grant.client_id, scope);
    sendJson(
      res,
      200,
      {
        access_token: access.token,
        token_type: "Bearer",
        expires_in: access.expires_in,
        refresh_token: refresh,
        scope: scope.join(" "),
      },
      { "cache-control": "no-store", pragma: "no-cache" },
    );
  }

  private async exchangeRefresh(
    form: URLSearchParams,
    res: ServerResponse,
  ): Promise<void> {
    // 동시 교환을 직렬화한다 — 둘 다 성공하는 갈림을 막는다.
    const prev = this.refreshChain;
    let release: () => void = () => undefined;
    this.refreshChain = new Promise<void>((r) => {
      release = r;
    });
    await prev;
    try {
      await this.exchangeRefreshLocked(form, res);
    } finally {
      release();
    }
  }

  private async exchangeRefreshLocked(
    form: URLSearchParams,
    res: ServerResponse,
  ): Promise<void> {
    const token = (form.get("refresh_token") ?? "").slice(0, 512);
    const client_id = (form.get("client_id") ?? "").slice(0, 256);
    // 등록된 정확한 client_id 필수 — 생략은 받지 않는다.
    if (!token || !client_id) {
      tokenError(
        res,
        400,
        "invalid_request",
        "refresh_token 과 client_id 필요",
      );
      return;
    }
    const wantScopeRaw = form.get("scope");
    let wantScope: string[] | null = null;
    if (wantScopeRaw !== null) {
      const parsed = parseScopeParam(wantScopeRaw);
      if (!parsed.ok) {
        tokenError(res, 400, "invalid_scope", parsed.reason);
        return;
      }
      wantScope = parsed.scopes;
    }
    // 검증·소비·회전·재사용판정 전체를 단일 저장소 트랜잭션에서.
    // 영속 실패·용량 초과 시 토큰을 발급하지 않는다(fail-closed).
    // 용량 거부는 트랜잭션 롤백으로 옛 live 토큰을 소진하지 않는다.
    let outcome: RefreshOutcome;
    try {
      outcome = await this.store.mutate((d) =>
        decideRefresh(d, {
          h: sha256Hex(token),
          client_id,
          wantScope,
          now: Date.now(),
          origin: this.config.publicOrigin,
          resource: this.config.resource,
          refreshTtlSecs: this.config.refreshTtlSecs,
        }),
      );
    } catch (e) {
      if (isStoreCapacityError(e)) {
        tokenError(res, 503, "temporarily_unavailable", "저장소 용량 초과");
        return;
      }
      tokenError(res, 500, "server_error", "일시적인 오류입니다");
      return;
    }
    if (!outcome.ok) {
      if (outcome.revokedGrant) this.dropMemoryForGrant(outcome.revokedGrant);
      tokenError(res, 400, outcome.error, outcome.description);
      return;
    }
    // 액세스 토큰은 durable 커밋 성공 후에만 발급·응답한다.
    const access = this.mintAccess(
      outcome.grant_id,
      outcome.client_id,
      outcome.scope,
    );
    sendJson(
      res,
      200,
      {
        access_token: access.token,
        token_type: "Bearer",
        expires_in: access.expires_in,
        refresh_token: outcome.next,
        scope: outcome.scope.join(" "),
      },
      { "cache-control": "no-store", pragma: "no-cache" },
    );
  }

  /* ─── 폐기(RFC7009) ──────────────────────────────────────── */

  async handleRevoke(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // 성공/실패를 구분하지 않는 일반 응답(토큰 존재 여부 비노출).
    // 단, 실제 영속 실패는 거짓 성공으로 알리지 않는다(503).
    const generic = (): void => {
      res.writeHead(200, {
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      });
      res.end();
    };
    const failed = (): void => {
      sendJson(
        res,
        503,
        { error: "temporarily_unavailable" },
        { "cache-control": "no-store", "retry-after": "60" },
      );
    };
    if (!isForm(req)) {
      generic();
      return;
    }
    const raw = await readBounded(req, MAX_TOKEN_FORM_BYTES);
    if (raw === null) {
      generic();
      return;
    }
    const form = new URLSearchParams(raw.toString("utf8"));
    if (hasDuplicates(form, ["token", "token_type_hint", "client_id"])) {
      sendJson(res, 400, { error: "invalid_request" });
      return;
    }
    const token = (form.get("token") ?? "").slice(0, 512);
    const client_id = (form.get("client_id") ?? "").slice(0, 256);
    if (!token) {
      generic();
      return;
    }
    if (token.startsWith(ACCESS_TOKEN_PREFIX)) {
      const rec = this.access.get(sha256Hex(token)) ?? null;
      // 유효한 토큰의 폐기는 grant/리프레시 계열 전체를 종료한다 —
      // 액세스 하나만 지우고 리프레시로 권한이 부활하게 두지 않는다.
      // 다른 클라이언트의 grant 는 건드리지 않는다.
      if (rec && (!client_id || rec.client_id === client_id)) {
        try {
          await this.revokeGrant(rec.grant_id);
        } catch {
          failed();
          return;
        }
      }
      generic();
      return;
    }
    if (token.startsWith(REFRESH_TOKEN_PREFIX)) {
      const rec = this.store.read((d) => d.refresh[sha256Hex(token)] ?? null);
      if (
        rec &&
        rec.consumed_at === null &&
        (!client_id || rec.client_id === client_id)
      ) {
        try {
          await this.revokeGrant(rec.grant_id);
        } catch {
          failed();
          return;
        }
      }
      generic();
      return;
    }
    generic();
  }

  /** grant 전체 폐기 — 리프레시 전부 + 메모리 액세스/코드 정리. */
  async revokeGrant(grant_id: string): Promise<void> {
    await this.store.mutate((d) => {
      const g = d.grants[grant_id];
      if (g) g.revoked_at = Date.now();
      for (const [h, r] of Object.entries(d.refresh)) {
        if (r.grant_id === grant_id) delete d.refresh[h];
      }
    });
    this.dropMemoryForGrant(grant_id);
  }

  private dropMemoryForGrant(grant_id: string): void {
    for (const [h, a] of this.access) {
      if (a.grant_id === grant_id) this.access.delete(h);
    }
    for (const [h, c] of this.codes) {
      if (c.grant_id === grant_id) this.codes.delete(h);
    }
  }

  /* ─── MCP 요청 인가 ──────────────────────────────────────── */

  /** 액세스 토큰을 검증하고 원본 키를 복호화 + 다운스트림 재검증한다.
   *  매 MCP HTTP 요청 전에 호출된다(sid 재사용 포함).
   *  validateKey await 사이 폐기·교체·만료를 막기 위해 성공 반환 직전
   *  현재 레코드를 원본 정체성과 동기 재검증한다(부활/교체 기록 거부). */
  async checkAccess(token: string): Promise<AccessResult> {
    const h = sha256Hex(token);
    const rec = this.access.get(h) ?? null;
    if (!rec) return { ok: false, kind: "invalid_token" };
    if (rec.expires_at <= Date.now()) {
      this.access.delete(h);
      return { ok: false, kind: "invalid_token" };
    }
    const grant = this.store.read((d) => d.grants[rec.grant_id] ?? null);
    if (!grant || grant.revoked_at !== null) {
      this.access.delete(h);
      return { ok: false, kind: "invalid_token" };
    }
    // grant 는 발급 시점의 정확한 issuer·resource 에 묶인다.
    // 설정 origin 이 바뀐 뒤 옛 grant 로 요청하면 거부한다.
    if (
      grant.issuer !== this.config.publicOrigin ||
      grant.resource !== this.config.resource
    ) {
      this.access.delete(h);
      return { ok: false, kind: "invalid_token" };
    }
    // await 전 원본 정체성 스냅샷 — await 후 현재값과 엄격 비교.
    const origScopeKey = [...rec.scope].sort().join(" ");
    const origGrantScopeKey = [...grant.scope].sort().join(" ");
    const origEnc = `${grant.enc.iv}.${grant.enc.data}.${grant.enc.tag}`;
    const origCreated = grant.created_at;
    const origExpires = rec.expires_at;
    const origGrantId = grant.grant_id;
    const origClientId = grant.client_id;
    const origOrg = grant.org_id;
    const origKey = grant.key_id;
    const origIssuer = grant.issuer;
    const origResource = grant.resource;
    // 원본 키는 서버 안에서만 복호화 — OAuth 토큰을 다운스트림에 보내지 않는다.
    const apiKey = decryptSecret(this.config.encryptionKey, grant.enc);
    if (!apiKey) {
      await this.revokeGrant(grant.grant_id);
      return { ok: false, kind: "invalid_token" };
    }
    // 원본 키 폐기를 즉시 반영 — 매 요청 읽기 전용 재검증.
    let ctx: AuthContext;
    try {
      ctx = await this.validateKey(apiKey);
    } catch {
      return { ok: false, kind: "upstream" };
    }
    if (!ctx.ok && (ctx.status === 401 || ctx.status === 403)) {
      await this.revokeGrant(origGrantId);
      return { ok: false, kind: "invalid_token" };
    }
    if (!ctx.ok) return { ok: false, kind: "upstream" };
    // dev/세션/비정형 컨텍스트(null·비UUID)는 거부 — 승인 조건과 동일.
    if (!isNonNilUuid(ctx.org_id) || !isNonNilUuid(ctx.key_id)) {
      await this.revokeGrant(origGrantId);
      return { ok: false, kind: "invalid_token" };
    }
    // await 사이 폐기·교체·만료 재검증 — 현재 레코드가 원본과 다르면 거부.
    // 부활/교체된 기록(같은 해시·다른 정체성)은 절대 인정하지 않는다.
    const rec2 = this.access.get(h) ?? null;
    const grant2 = this.store.read((d) => d.grants[origGrantId] ?? null);
    const mismatch =
      !rec2 ||
      !grant2 ||
      grant2.revoked_at !== null ||
      rec2.grant_id !== origGrantId ||
      rec2.client_id !== origClientId ||
      rec2.expires_at !== origExpires ||
      rec2.expires_at <= Date.now() ||
      [...rec2.scope].sort().join(" ") !== origScopeKey ||
      grant2.grant_id !== origGrantId ||
      grant2.client_id !== origClientId ||
      grant2.org_id !== origOrg ||
      grant2.key_id !== origKey ||
      grant2.issuer !== origIssuer ||
      grant2.resource !== origResource ||
      grant2.created_at !== origCreated ||
      [...grant2.scope].sort().join(" ") !== origGrantScopeKey ||
      `${grant2.enc.iv}.${grant2.enc.data}.${grant2.enc.tag}` !== origEnc ||
      grant2.issuer !== this.config.publicOrigin ||
      grant2.resource !== this.config.resource;
    if (mismatch) {
      this.access.delete(h);
      return { ok: false, kind: "invalid_token" };
    }
    // 승인 시점 바인딩과 엄격 비교 — org/키가 바뀌었으면 grant 무효.
    // 현재 grant2 기준(원본이 아닌)으로 판정한다.
    if (grant2.org_id !== ctx.org_id || grant2.key_id !== ctx.key_id) {
      await this.revokeGrant(origGrantId);
      return { ok: false, kind: "invalid_token" };
    }
    const scope = [...rec2.scope].sort();
    return {
      ok: true,
      check: {
        apiKey,
        grant_id: grant2.grant_id,
        client_id: grant2.client_id,
        scope,
        scopeKey: scope.join(" "),
        expires_at: rec2.expires_at,
        org_id: grant2.org_id as string,
        key_id: grant2.key_id as string,
      },
    };
  }

  /** 디스패치 경계 동기 인가 가드 — 본문 읽기·세션 연결 등 모든 await 뒤
   *  transport 호출 직전에 현재 레코드를 재확인한다. 네트워크 await 없이
   *  동기 판정하므로 새로운 레이스 간극을 만들지 않는다. */
  verifyLiveAccess(
    token: string,
    expected: {
      grant_id: string;
      client_id: string;
      scopeKey: string;
      expires_at: number;
      org_id: string;
      key_id: string;
    },
  ): boolean {
    const h = sha256Hex(token);
    const rec = this.access.get(h) ?? null;
    if (!rec) return false;
    if (rec.expires_at <= Date.now()) {
      this.access.delete(h);
      return false;
    }
    if (
      rec.grant_id !== expected.grant_id ||
      rec.client_id !== expected.client_id ||
      rec.expires_at !== expected.expires_at ||
      [...rec.scope].sort().join(" ") !== expected.scopeKey
    ) {
      return false;
    }
    const grant = this.store.read((d) => d.grants[rec.grant_id] ?? null);
    if (!grant || grant.revoked_at !== null) {
      this.access.delete(h);
      return false;
    }
    if (
      grant.grant_id !== expected.grant_id ||
      grant.client_id !== expected.client_id ||
      grant.org_id !== expected.org_id ||
      grant.key_id !== expected.key_id ||
      grant.issuer !== this.config.publicOrigin ||
      grant.resource !== this.config.resource
    ) {
      this.access.delete(h);
      return false;
    }
    return true;
  }
}

/* ─── 모듈 헬퍼 ───────────────────────────────────────────────── */

function hostnameOf(host: string): string {
  const h = host.trim().toLowerCase();
  if (h.startsWith("[")) {
    const end = h.indexOf("]");
    return end > 0 ? h.slice(1, end) : h;
  }
  const idx = h.lastIndexOf(":");
  // 포트 없는 호스트명 또는 IPv6 리터럴(대괄호 없음) 처리.
  if (idx >= 0 && h.indexOf(":") === idx) return h.slice(0, idx);
  return h;
}

function trimMap<K, V>(m: Map<K, V>, max: number): void {
  while (m.size > max) {
    const first = m.keys().next();
    if (first.done) break;
    m.delete(first.value);
  }
}

export { escapeHtml };
