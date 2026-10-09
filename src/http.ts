#!/usr/bin/env node
/** loftbox-mcp 원격 HTTP 진입 — Streamable HTTP transport (stateful 세션).
 *
 * 호스팅 remote MCP: 클라이언트(Claude/ChatGPT 등)가 mcp.loftbox.net 에 연결한다.
 * 인증은 두 가지다:
 * 1. 레거시 raw 키 — `Authorization: Bearer <LoftBox API key>`. 기존 동작 유지.
 * 2. OAuth 브로커(선택) — 브라우저 승인으로 발급된 opaque 토큰(`lbmcp_at_…`).
 *    활성화 시에만 동작하며, 원본 키는 서버 안에서만 복호화된다.
 *
 * MCP 는 initialize→이후 요청의 stateful 생명주기라 세션을 유지한다: initialize POST 시
 * 세션 생성(mcp-session-id 발급) + 그 키로 server 생성, 후속 요청은 session-id 로 재사용.
 * raw 세션은 apiKey 에, OAuth 세션은 grant+scope 에 바인딩된다(리프레시 후에도
 * 같은 grant+scope 면 sid 재사용, grant 교체·폐기 시 재사용 불가).
 * 127.0.0.1 바인딩(Caddy 가 mcp.loftbox.net → 여기로 리버스 프록시 + TLS).
 */

import { createServer as createHttpServer } from "node:http";
import type { IncomingMessage, ServerResponse, Server } from "node:http";
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  createServer as createMcpServer,
  allowedToolsForScope,
  isReadOnlyFromEnv,
  logStderr,
  SERVER_NAME,
  SERVER_VERSION,
} from "./server.js";
import {
  loadOAuthConfig,
  looksLikeOAuthToken,
  type OAuthTestOverrides,
} from "./oauth-config.js";
import { FileOAuthStore } from "./oauth-store.js";
import { OAuthBroker } from "./oauth.js";
import { renderErrorPage, renderSetupPage } from "./oauth-html.js";

const PORT = Number(process.env.LOFTBOX_MCP_PORT ?? "3100");
const HOST = process.env.LOFTBOX_MCP_HOST ?? "127.0.0.1";
const MCP_PATH = "/mcp";
const MAX_BODY_BYTES = 1_000_000;
const SESSION_IDLE_MS = 30 * 60 * 1000; // 30분 유휴 후 정리
const MAX_SESSIONS = 2000; // 세션맵 상한(메모리 DoS 백스톱)
const DEFAULT_BASE_URL = "https://api.loftbox.net";

export interface HttpServerOptions {
  /** 테스트 전용 OAuth 오버라이드(루프백 허용·TTL 단축). 운영 기본값 아님. */
  oauth?: OAuthTestOverrides;
}

function resolvedBaseUrl(): string {
  return process.env.LOFTBOX_BASE_URL ?? DEFAULT_BASE_URL;
}

/** initialize 시 api_key 선검증 — 잘못된 키로 세션(서버측 상태)을 만들지 않는다.
 *  GET {base}/v1 는 protected 라우트라 유효 키면 2xx, 아니면 401. (tool 호출 0회/세션 1회만.) */
async function validateApiKey(
  apiKey: string,
  baseUrl: string,
): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl.replace(/\/+$/, "")}/v1`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    return res.ok;
  } catch {
    return false;
  }
}

type SessionAuth =
  | { kind: "raw"; apiKey: string }
  | { kind: "oauth"; grantId: string; scopeKey: string; clientId: string };

interface Session {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  auth: SessionAuth;
  lastUsed: number;
}

interface ServerState {
  sessions: Map<string, Session>;
  broker: OAuthBroker | null;
}

function extractBearer(req: IncomingMessage): string | null {
  const h = req.headers["authorization"];
  if (typeof h !== "string") return null;
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m && m[1] ? m[1].trim() : null;
}

function sessionIdOf(req: IncomingMessage): string | undefined {
  const h = req.headers["mcp-session-id"];
  return typeof h === "string" ? h : undefined;
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) throw new Error("request body too large");
    chunks.push(buf);
  }
  if (chunks.length === 0) return undefined;
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw.trim()) return undefined;
  return JSON.parse(raw) as unknown;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "content-type": "application/json",
    "x-content-type-options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; " +
      "form-action 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
  });
  res.end(html);
}

function jsonRpcError(code: number, message: string): unknown {
  return { jsonrpc: "2.0", error: { code, message }, id: null };
}

function wwwAuthenticate(broker: OAuthBroker | null): string {
  if (broker) return broker.wwwAuthenticate();
  return 'Bearer realm="loftbox-mcp"';
}

function dropSession(state: ServerState, sid: string): void {
  const s = state.sessions.get(sid);
  if (!s) return;
  state.sessions.delete(sid);
  void s.transport.close();
  void s.server.close();
}

async function handleMcp(
  state: ServerState,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const broker = state.broker;
  // OAuth 활성 시 /mcp 도 신뢰 Host 검사(DNS 리바인딩 가드).
  // 비활성 레거시 경로는 그대로 둔다.
  if (broker && !broker.hostOk(req)) {
    sendJson(res, 400, jsonRpcError(-32000, "신뢰할 수 없는 호스트"));
    return;
  }
  // Origin 이 있으면 신뢰값만 허용한다(없으면 서버간 호출로 통과).
  if (broker && !broker.mcpOriginOk(req)) {
    sendJson(res, 403, jsonRpcError(-32001, "허용되지 않은 Origin"));
    return;
  }
  const token = extractBearer(req);
  if (!token) {
    res.setHeader("WWW-Authenticate", wwwAuthenticate(broker));
    sendJson(
      res,
      401,
      jsonRpcError(
        -32001,
        "Authorization: Bearer <LoftBox API key> 가 필요합니다",
      ),
    );
    return;
  }

  // OAuth 토큰 분기 — raw 키 인증으로 절대 폴백하지 않는다.
  if (looksLikeOAuthToken(token)) {
    if (!broker) {
      res.setHeader("WWW-Authenticate", wwwAuthenticate(null));
      sendJson(
        res,
        401,
        jsonRpcError(-32001, "OAuth 토큰이 유효하지 않습니다"),
      );
      return;
    }
    const checked = await broker.checkAccess(token);
    if (!checked.ok) {
      if (checked.kind === "upstream") {
        sendJson(res, 503, jsonRpcError(-32000, "LoftBox API 연결 실패"));
        return;
      }
      res.setHeader("WWW-Authenticate", broker.wwwAuthenticate());
      sendJson(
        res,
        401,
        jsonRpcError(-32001, "OAuth 토큰이 유효하지 않습니다"),
      );
      return;
    }
    await handleMcpSession(state, req, res, {
      kind: "oauth",
      token,
      apiKey: checked.check.apiKey,
      allowedTools: allowedToolsForScope(
        checked.check.scope,
        isReadOnlyFromEnv(),
      ),
      grantId: checked.check.grant_id,
      scopeKey: checked.check.scopeKey,
      clientId: checked.check.client_id,
      expiresAt: checked.check.expires_at,
      orgId: checked.check.org_id,
      keyId: checked.check.key_id,
    });
    return;
  }

  await handleMcpSession(state, req, res, { kind: "raw", apiKey: token });
}

interface OAuthSessionInit {
  kind: "oauth";
  /** 원본 액세스 토큰 — 디스패치 경계 동기 재검증용(로그·하류 미전달). */
  token: string;
  apiKey: string;
  allowedTools: string[];
  grantId: string;
  scopeKey: string;
  clientId: string;
  expiresAt: number;
  orgId: string;
  keyId: string;
}

interface RawSessionInit {
  kind: "raw";
  apiKey: string;
}

async function handleMcpSession(
  state: ServerState,
  req: IncomingMessage,
  res: ServerResponse,
  init: OAuthSessionInit | RawSessionInit,
): Promise<void> {
  const broker = state.broker;
  let body: unknown;
  if (req.method === "POST") {
    try {
      body = await readJsonBody(req);
    } catch {
      sendJson(res, 400, jsonRpcError(-32700, "잘못된 JSON 본문"));
      return;
    }
  }

  const sid = sessionIdOf(req);
  let transport: StreamableHTTPServerTransport;

  if (sid) {
    const existing = state.sessions.get(sid);
    if (!existing) {
      sendJson(
        res,
        404,
        jsonRpcError(-32001, "세션을 찾을 수 없습니다(만료/무효)"),
      );
      return;
    }
    // 세션 바인딩: raw 는 Bearer 일치, OAuth 는 grant+scope 일치.
    if (init.kind === "raw") {
      if (
        existing.auth.kind !== "raw" ||
        existing.auth.apiKey !== init.apiKey
      ) {
        sendJson(res, 403, jsonRpcError(-32001, "세션 인증 불일치"));
        return;
      }
    } else {
      if (
        existing.auth.kind !== "oauth" ||
        existing.auth.grantId !== init.grantId ||
        existing.auth.scopeKey !== init.scopeKey
      ) {
        sendJson(res, 403, jsonRpcError(-32001, "세션 인증 불일치"));
        return;
      }
    }
    existing.lastUsed = Date.now();
    transport = existing.transport;
  } else if (req.method === "POST" && isInitializeRequest(body)) {
    if (state.sessions.size >= MAX_SESSIONS) {
      sendJson(
        res,
        503,
        jsonRpcError(-32000, "세션 한도 초과 — 잠시 후 재시도"),
      );
      return;
    }
    const baseUrl = resolvedBaseUrl();
    if (init.kind === "raw") {
      // 키 선검증: 잘못된 키로 세션 생성 차단(메모리 DoS·미인증 상태 방지).
      if (!(await validateApiKey(init.apiKey, baseUrl))) {
        res.setHeader("WWW-Authenticate", wwwAuthenticate(broker));
        sendJson(res, 401, jsonRpcError(-32001, "API 키가 유효하지 않습니다"));
        return;
      }
    }
    // read-only 는 서버 env 설정 — 클라이언트 인자로 받지 않는다.
    // OAuth 는 scope allowlist 를 추가로 적용한다.
    const server = createMcpServer({
      apiKey: init.apiKey,
      baseUrl,
      readOnly: isReadOnlyFromEnv(),
      ...(init.kind === "oauth" ? { allowedTools: init.allowedTools } : {}),
    });
    const auth: SessionAuth =
      init.kind === "raw"
        ? { kind: "raw", apiKey: init.apiKey }
        : {
            kind: "oauth",
            grantId: init.grantId,
            scopeKey: init.scopeKey,
            clientId: init.clientId,
          };
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (newSid: string) => {
        state.sessions.set(newSid, {
          transport,
          server,
          auth,
          lastUsed: Date.now(),
        });
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) dropSession(state, transport.sessionId);
    };
    await server.connect(transport);
  } else {
    sendJson(
      res,
      400,
      jsonRpcError(
        -32000,
        "유효한 세션(mcp-session-id) 또는 initialize 요청이 필요합니다",
      ),
    );
    return;
  }

  // 디스패치 경계 동기 가드 — 본문 읽기·세션 연결 await 사이 폐기·만료를
  // transport 호출 직전에 동기 재확인한다. 네트워크 await 없이 판정하므로
  // 새로운 간극을 만들지 않는다. raw 경로는 그대로 둔다.
  if (init.kind === "oauth" && broker) {
    const live = broker.verifyLiveAccess(init.token, {
      grant_id: init.grantId,
      client_id: init.clientId,
      scopeKey: init.scopeKey,
      expires_at: init.expiresAt,
      org_id: init.orgId,
      key_id: init.keyId,
    });
    if (!live) {
      res.setHeader("WWW-Authenticate", broker.wwwAuthenticate());
      sendJson(
        res,
        401,
        jsonRpcError(-32001, "OAuth 토큰이 유효하지 않습니다"),
      );
      return;
    }
  }

  await transport.handleRequest(req, res, body);
}

/** /oauth/* 공통 가드 — Host 검증 + 속도 제한. 실패 시 응답 후 false. */
function oauthGuard(
  broker: OAuthBroker,
  req: IncomingMessage,
  res: ServerResponse,
  html: boolean,
): boolean {
  if (!broker.hostOk(req)) {
    if (html) {
      sendHtml(
        res,
        400,
        renderErrorPage("요청 오류", "신뢰할 수 없는 호스트입니다."),
      );
    } else {
      sendJson(res, 400, { error: "invalid_request" });
    }
    return false;
  }
  if (!broker.checkRate(req)) {
    res.setHeader("retry-after", "60");
    if (html) {
      sendHtml(
        res,
        429,
        renderErrorPage(
          "요청 초과",
          "요청이 너무 많습니다. 잠시 후 다시 시도하세요.",
        ),
      );
    } else {
      sendJson(res, 429, { error: "temporarily_unavailable" });
    }
    return false;
  }
  return true;
}

function methodNotAllowed(res: ServerResponse, allow: string): void {
  res.writeHead(405, { allow, "content-type": "application/json" });
  res.end(JSON.stringify({ error: "method not allowed" }));
}

export function buildHttpServer(opts: HttpServerOptions = {}): Server {
  // OAuth 는 선택 활성화 — 켜져 있는데 설정이 유효하지 않으면 기동 중단.
  const oauthConfig = loadOAuthConfig(process.env, opts.oauth ?? {});
  let broker: OAuthBroker | null = null;
  if (oauthConfig) {
    const o = opts.oauth ?? {};
    broker = new OAuthBroker(
      oauthConfig,
      FileOAuthStore.open(oauthConfig.storePath, {
        refreshTtlMs: oauthConfig.refreshTtlSecs * 1000,
        ...(o.maxStoreBytes !== undefined
          ? { maxStoreBytes: o.maxStoreBytes }
          : {}),
        ...(o.maxClients !== undefined ? { maxClients: o.maxClients } : {}),
        ...(o.maxGrants !== undefined ? { maxGrants: o.maxGrants } : {}),
        ...(o.maxRefreshTokens !== undefined
          ? { maxRefreshTokens: o.maxRefreshTokens }
          : {}),
      }),
    );
  }
  const state: ServerState = { sessions: new Map(), broker };

  const server = createHttpServer((req, res) => {
    const path = (req.url ?? "").split("?")[0] ?? "";
    try {
      if (path === "/health") {
        if (req.method !== "GET") {
          methodNotAllowed(res, "GET");
          return;
        }
        sendJson(res, 200, {
          status: "ok",
          server: SERVER_NAME,
          version: SERVER_VERSION,
          oauth_enabled: broker !== null,
          ...(broker
            ? {
                resource: broker.config.resource,
                issuer: broker.config.publicOrigin,
              }
            : {}),
        });
        return;
      }
      if (path === "/" || path === "/setup") {
        if (req.method !== "GET") {
          methodNotAllowed(res, "GET");
          return;
        }
        sendHtml(
          res,
          200,
          renderSetupPage({
            oauthEnabled: broker !== null,
            resource: broker ? broker.config.resource : null,
            issuer: broker ? broker.config.publicOrigin : null,
          }),
        );
        return;
      }
      if (
        path === "/.well-known/oauth-protected-resource" ||
        path === "/.well-known/oauth-protected-resource/mcp"
      ) {
        if (!broker) {
          sendJson(res, 404, { error: "not found" });
          return;
        }
        if (req.method !== "GET") {
          methodNotAllowed(res, "GET");
          return;
        }
        broker.handleMetadata(res);
        return;
      }
      if (path === "/.well-known/oauth-authorization-server") {
        if (!broker) {
          sendJson(res, 404, { error: "not found" });
          return;
        }
        if (req.method !== "GET") {
          methodNotAllowed(res, "GET");
          return;
        }
        broker.handleAuthServerMetadata(res);
        return;
      }
      if (path === "/oauth/register") {
        if (!broker) {
          sendJson(res, 404, { error: "not found" });
          return;
        }
        if (req.method !== "POST") {
          methodNotAllowed(res, "POST");
          return;
        }
        if (!oauthGuard(broker, req, res, false)) return;
        broker.handleRegister(req, res).catch((e) => {
          logStderr(`OAuth 등록 오류: ${(e as Error)?.message ?? String(e)}`);
          if (!res.headersSent) sendJson(res, 500, { error: "server_error" });
        });
        return;
      }
      if (path === "/oauth/authorize") {
        if (!broker) {
          sendJson(res, 404, { error: "not found" });
          return;
        }
        if (req.method !== "GET" && req.method !== "POST") {
          methodNotAllowed(res, "GET, POST");
          return;
        }
        if (!oauthGuard(broker, req, res, true)) return;
        const p =
          req.method === "GET"
            ? broker.handleAuthorizeGet(req, res)
            : broker.handleAuthorizePost(req, res);
        p.catch((e) => {
          logStderr(`OAuth 인가 오류: ${(e as Error)?.message ?? String(e)}`);
          if (!res.headersSent)
            sendHtml(
              res,
              500,
              renderErrorPage("내부 오류", "일시적인 오류입니다."),
            );
        });
        return;
      }
      if (path === "/oauth/token") {
        if (!broker) {
          sendJson(res, 404, { error: "not found" });
          return;
        }
        if (req.method !== "POST") {
          methodNotAllowed(res, "POST");
          return;
        }
        if (!oauthGuard(broker, req, res, false)) return;
        broker.handleToken(req, res).catch((e) => {
          logStderr(`OAuth 토큰 오류: ${(e as Error)?.message ?? String(e)}`);
          if (!res.headersSent)
            sendJson(res, 500, {
              error: "server_error",
            });
        });
        return;
      }
      if (path === "/oauth/revoke") {
        if (!broker) {
          sendJson(res, 404, { error: "not found" });
          return;
        }
        if (req.method !== "POST") {
          methodNotAllowed(res, "POST");
          return;
        }
        if (!oauthGuard(broker, req, res, false)) return;
        broker.handleRevoke(req, res).catch((e) => {
          logStderr(`OAuth 폐기 오류: ${(e as Error)?.message ?? String(e)}`);
          // 영속 실패를 성공으로 알리지 않는다 — 미지 토큰의 일반 200 과
          // 달리 인프라 실패는 503 으로 fail-closed 한다.
          if (!res.headersSent) {
            sendJson(res, 503, { error: "temporarily_unavailable" });
          }
        });
        return;
      }
      if (path === MCP_PATH) {
        handleMcp(state, req, res).catch((e) => {
          logStderr(`MCP 요청 처리 오류: ${(e as Error)?.stack ?? String(e)}`);
          if (!res.headersSent)
            sendJson(res, 500, jsonRpcError(-32603, "내부 오류"));
        });
        return;
      }
      sendJson(res, 404, { error: "not found" });
    } catch (e) {
      logStderr(`라우팅 오류: ${(e as Error)?.message ?? String(e)}`);
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
    }
  });

  // 유휴 세션 주기 정리(메모리 누수 방지) — 서버별 타이머, close 시 해제.
  const sweep = setInterval(
    () => {
      const now = Date.now();
      for (const [sid, s] of state.sessions) {
        if (now - s.lastUsed > SESSION_IDLE_MS) dropSession(state, sid);
      }
    },
    5 * 60 * 1000,
  );
  sweep.unref();
  server.on("close", () => {
    clearInterval(sweep);
    for (const sid of [...state.sessions.keys()]) dropSession(state, sid);
  });
  return server;
}

function isMain(): boolean {
  const entry = process.argv[1];
  return !!entry && import.meta.url === pathToFileURL(entry).href;
}

if (isMain()) {
  let server: Server;
  try {
    server = buildHttpServer();
  } catch (e) {
    logStderr(`기동 실패: ${(e as Error)?.message ?? String(e)}`);
    process.exit(1);
  }
  server.listen(PORT, HOST, () => {
    logStderr(
      `${SERVER_NAME} v${SERVER_VERSION} remote MCP listening on http://${HOST}:${PORT}${MCP_PATH}`,
    );
  });
}
