/** OAuth 브로커 설정 — fail-closed 파싱/검증.
 *
 * 활성화는 전부 명시적 운영자 설정이 필요하다:
 * - LOFTBOX_MCP_OAUTH_ENABLED=true (기본 비활성 → 기존 raw 키 런타임 유지)
 * - LOFTBOX_MCP_PUBLIC_URL: 신뢰할 수 있는 절대 HTTPS 공개 origin
 * - LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY: 32바이트 base64 암호화 비밀(별도 보관)
 * - LOFTBOX_MCP_OAUTH_STORE: 절대 경로의 durable 비공개 저장소
 *   (/opt/loftbox-mcp 밖 — deploy.sh 가 그 디렉터리를 삭제한다)
 *
 * 활성화 상태에서 설정이 하나라도 유효하지 않으면 예외를 던져 기동을
 * 중단한다(조용한 비활성 폴백 없음). 루프백 HTTP 는 운영 기본값에서 절대
 * 허용하지 않으며, 테스트 코드가 프로그래밍 방식으로만
 * (HttpServerOptions.oauthAllowInsecureLoopback) 켤 수 있다.
 */

import { posix } from "node:path";

export const OAUTH_SCOPE_READ = "loftbox.read";
export const OAUTH_SCOPE_MANAGE = "loftbox.manage";
export const OAUTH_SCOPES = [OAUTH_SCOPE_READ, OAUTH_SCOPE_MANAGE] as const;

/** 발급 토큰 프리픽스 — raw API 키와 혼동되지 않게 구분된다. */
export const ACCESS_TOKEN_PREFIX = "lbmcp_at_";
export const REFRESH_TOKEN_PREFIX = "lbmcp_rt_";
/** OAuth 계열로 보이는 입력(액세스/리프레시/코드 프리픽스). */
const OAUTH_LOOKING_PREFIXES = [
  ACCESS_TOKEN_PREFIX,
  REFRESH_TOKEN_PREFIX,
  "lbmcp_ac_",
] as const;

export function looksLikeOAuthToken(token: string): boolean {
  return OAUTH_LOOKING_PREFIXES.some((p) => token.startsWith(p));
}

/** 기본 TTL. */
export const DEFAULT_ACCESS_TTL_SECS = 600; // 10분
export const DEFAULT_REFRESH_TTL_SECS = 30 * 24 * 3600; // 30일
export const DEFAULT_CODE_TTL_SECS = 300; // 5분
export const DEFAULT_TXN_TTL_SECS = 600; // 10분

/** 입력 상한. */
export const MAX_QUERY_CHARS = 8192;
export const MAX_FORM_BYTES = 32 * 1024;
export const MAX_TOKEN_FORM_BYTES = 16 * 1024;
export const MAX_DCR_BODY_BYTES = 32 * 1024;
export const MAX_REDIRECT_URIS = 10;
export const MAX_URI_CHARS = 2048;
export const MAX_CLIENT_NAME_CHARS = 128;
export const MAX_STATE_CHARS = 2048;
export const MAX_SCOPE_CHARS = 256;
export const MAX_API_KEY_CHARS = 512;
export const MAX_TXN_ATTEMPTS = 5;

/** 저장소 상한(단일 프로세스, 메모리/파일 DoS 백스톱). */
export const MAX_CLIENTS = 2000;
export const MAX_GRANTS = 10000;
export const MAX_REFRESH_TOKENS = 20000;
export const MAX_ACCESS_TOKENS = 20000;
export const MAX_CODES = 5000;
export const MAX_TXNS = 5000;

/** 속도 제한: IP당 60초 윈도우 허용 횟수(베스트 에포트). */
export const RATE_LIMIT_WINDOW_MS = 60_000;
export const RATE_LIMIT_MAX = 300;
export const MAX_RATE_IPS = 5000;

/** 다운스트림 키 검증 타임아웃. */
export const KEY_VALIDATION_TIMEOUT_MS = 10_000;

export interface OAuthConfig {
  /** 정규화된 공개 origin — issuer (후행 슬래시 없음). */
  publicOrigin: string;
  /** 정규 리소스 식별자 — publicOrigin + "/mcp". */
  resource: string;
  /** 32바이트 암호화 키(메모리 보관, 로그/응답에 절대 노출 금지). */
  encryptionKey: Buffer;
  /** durable 저장소 파일 절대 경로. */
  storePath: string;
  /** 테스트 전용: 루프백 HTTP origin/redirect 허용. */
  allowInsecureLoopback: boolean;
  accessTtlSecs: number;
  refreshTtlSecs: number;
  codeTtlSecs: number;
  txnTtlSecs: number;
}

export interface OAuthTestOverrides {
  allowInsecureLoopback?: boolean;
  accessTtlSecs?: number;
  refreshTtlSecs?: number;
  codeTtlSecs?: number;
  txnTtlSecs?: number;
  /** 테스트 전용 저장소 상한 오버라이드 — 운영 기본은 모듈 상수. */
  maxStoreBytes?: number;
  maxClients?: number;
  maxGrants?: number;
  maxRefreshTokens?: number;
}

function fail(msg: string): never {
  throw new Error(`OAuth 설정 오류: ${msg}`);
}

export function isLoopbackHostname(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return (
    h === "localhost" ||
    h === "127.0.0.1" ||
    h === "::1" ||
    h === "[::1]" ||
    h.startsWith("127.") ||
    h.endsWith(".localhost")
  );
}

/** origin 문자열을 파싱·정규화한다. 실패하면 null. */
export function parseOrigin(raw: string): string | null {
  if (!raw || raw.length > MAX_URI_CHARS) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.username || u.password) return null;
  if (u.pathname !== "/" && u.pathname !== "") return null;
  if (u.search || u.hash) return null;
  return u.origin === "null" ? null : u.origin;
}

function parseTtl(
  value: number | undefined,
  fallback: number,
  name: string,
): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value <= 0 || value > 366 * 24 * 3600) {
    fail(`${name} TTL이 범위를 벗어났습니다`);
  }
  return value;
}

/** env + 테스트 오버라이드에서 OAuth 설정을 로드한다.
 *  비활성(false)이면 null 반환. 활성인데 유효하지 않으면 throw. */
export function loadOAuthConfig(
  env: Record<string, string | undefined>,
  overrides: OAuthTestOverrides = {},
): OAuthConfig | null {
  const enabled = (env.LOFTBOX_MCP_OAUTH_ENABLED ?? "").trim().toLowerCase();
  if (enabled !== "true") return null;

  const allowInsecureLoopback = overrides.allowInsecureLoopback === true;

  const publicRaw = (env.LOFTBOX_MCP_PUBLIC_URL ?? "").trim();
  if (!publicRaw) fail("LOFTBOX_MCP_PUBLIC_URL 이 필요합니다");
  const publicOrigin = parseOrigin(publicRaw);
  if (!publicOrigin)
    fail("LOFTBOX_MCP_PUBLIC_URL 은 절대 origin 이어야 합니다");
  const pUrl = new URL(publicOrigin);
  if (pUrl.protocol === "https:") {
    // 정상 운영 경로.
  } else if (
    allowInsecureLoopback &&
    pUrl.protocol === "http:" &&
    isLoopbackHostname(pUrl.hostname)
  ) {
    // 테스트 전용 루프백 허용.
  } else {
    fail(
      "LOFTBOX_MCP_PUBLIC_URL 은 https origin 이어야 합니다 " +
        "(루프백 http 는 테스트 설정에서만 허용)",
    );
  }

  const encRaw = (env.LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY ?? "").trim();
  if (!encRaw) fail("LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY 가 필요합니다");
  let encryptionKey: Buffer;
  try {
    encryptionKey = Buffer.from(encRaw, "base64");
  } catch {
    fail("LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY 은 base64 이어야 합니다");
  }
  if (encryptionKey.length !== 32 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encRaw)) {
    fail("LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY 은 32바이트 base64 이어야 합니다");
  }

  const storeRaw = (env.LOFTBOX_MCP_OAUTH_STORE ?? "").trim();
  if (!storeRaw) fail("LOFTBOX_MCP_OAUTH_STORE 경로가 필요합니다");
  if (!storeRaw.startsWith("/")) {
    fail("LOFTBOX_MCP_OAUTH_STORE 은 절대 경로이어야 합니다");
  }
  // `..`/중복 슬래시 우회를 막기 위해 정규화 후 제외 디렉터리를 검사한다.
  const storePath = posix.normalize(storeRaw);
  if (
    storePath === "/opt/loftbox-mcp" ||
    storePath.startsWith("/opt/loftbox-mcp/")
  ) {
    fail(
      "LOFTBOX_MCP_OAUTH_STORE 은 /opt/loftbox-mcp 밖이어야 합니다(deploy.sh 삭제 대상)",
    );
  }

  return {
    publicOrigin,
    resource: `${publicOrigin}/mcp`,
    encryptionKey,
    storePath,
    allowInsecureLoopback,
    accessTtlSecs: parseTtl(
      overrides.accessTtlSecs,
      DEFAULT_ACCESS_TTL_SECS,
      "access",
    ),
    refreshTtlSecs: parseTtl(
      overrides.refreshTtlSecs,
      DEFAULT_REFRESH_TTL_SECS,
      "refresh",
    ),
    codeTtlSecs: parseTtl(overrides.codeTtlSecs, DEFAULT_CODE_TTL_SECS, "code"),
    txnTtlSecs: parseTtl(overrides.txnTtlSecs, DEFAULT_TXN_TTL_SECS, "txn"),
  };
}

/** redirect URI 후보를 검증한다. 통과하면 정규형(입력 그대로, exact match 용),
 *  실패하면 오류 사유를 반환한다. */
export function validateRedirectUri(
  candidate: unknown,
  allowInsecureLoopback: boolean,
): { ok: true; uri: string } | { ok: false; reason: string } {
  if (typeof candidate !== "string") {
    return { ok: false, reason: "redirect_uri 는 문자열이어야 합니다" };
  }
  if (candidate.length === 0 || candidate.length > MAX_URI_CHARS) {
    return { ok: false, reason: "redirect_uri 길이 초과" };
  }
  let u: URL;
  try {
    u = new URL(candidate);
  } catch {
    return { ok: false, reason: "redirect_uri 파싱 실패" };
  }
  if (u.hash) return { ok: false, reason: "redirect_uri 에 fragment 금지" };
  if (u.username || u.password) {
    return { ok: false, reason: "redirect_uri 에 userinfo 금지" };
  }
  if (u.hostname.includes("*")) {
    return { ok: false, reason: "redirect_uri 와일드카드 금지" };
  }
  if (u.protocol === "https:") {
    if (isLoopbackHostname(u.hostname)) {
      return { ok: false, reason: "루프백은 http 테스트 설정에서만 허용" };
    }
    return { ok: true, uri: candidate };
  }
  if (
    allowInsecureLoopback &&
    u.protocol === "http:" &&
    isLoopbackHostname(u.hostname)
  ) {
    return { ok: true, uri: candidate };
  }
  return { ok: false, reason: "redirect_uri 는 https 이어야 합니다" };
}

/** 공백 구분 scope 문자열을 파싱한다. 빈 값이면 기본 read.
 *  manage 는 read 를 포함하는 프로필이므로 manage 단독 요청도
 *  read 를 함께 포함하도록 정규화한다 — 미체크 시 읽기 축소(거부 아님),
 *  체크 시 관리 프로필(읽기+관리)이 일관되게 부여된다. */
export function parseScopeParam(
  raw: string | null,
): { ok: true; scopes: string[] } | { ok: false; reason: string } {
  if (raw === null || raw.trim() === "")
    return { ok: true, scopes: [OAUTH_SCOPE_READ] };
  if (raw.length > MAX_SCOPE_CHARS) {
    return { ok: false, reason: "scope 길이 초과" };
  }
  const parts = raw.split(/\s+/).filter(Boolean);
  const unique = [...new Set(parts)];
  for (const s of unique) {
    if (s !== OAUTH_SCOPE_READ && s !== OAUTH_SCOPE_MANAGE) {
      return { ok: false, reason: `알 수 없는 scope: ${s}` };
    }
  }
  if (
    unique.includes(OAUTH_SCOPE_MANAGE) &&
    !unique.includes(OAUTH_SCOPE_READ)
  ) {
    unique.push(OAUTH_SCOPE_READ);
  }
  return { ok: true, scopes: unique };
}

/** 저장 scope 를 프로필 의미로 정규화 — manage 는 read 를 내포한다.
 *  구버전 manage 단독 grant 의 부분집합 검사 호환용. */
export function effectiveScopes(scope: readonly string[]): string[] {
  if (scope.includes(OAUTH_SCOPE_MANAGE) && !scope.includes(OAUTH_SCOPE_READ)) {
    return [...scope, OAUTH_SCOPE_READ];
  }
  return [...scope];
}

/** PKCE verifier 문자셋/길이 검증(RFC7636 43..128). */
export function isValidVerifier(v: string): boolean {
  return v.length >= 43 && v.length <= 128 && /^[A-Za-z0-9\-._~]+$/.test(v);
}

/** PKCE S256 challenge 정확 형태 검증 — BASE64URL(SHA256(verifier))는
 *  항상 43자이므로 그 외 길이를 거부한다(RFC7636 §4.2). */
export function isValidChallenge(c: string): boolean {
  return c.length === 43 && /^[A-Za-z0-9\-_]+$/.test(c);
}

const UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const NIL_UUID = "00000000-0000-0000-0000-000000000000";

/** null이 아닌 non-nil UUID인지 — 브라우저 키 승인과 요청 검증의
 *  조직/키 바인딩에 사용한다. dev/세션 폴백·비정형 값은 거부된다. */
export function isNonNilUuid(v: string | null | undefined): v is string {
  return (
    typeof v === "string" && UUID_RE.test(v) && v.toLowerCase() !== NIL_UUID
  );
}
