#!/usr/bin/env node
/** loftbox-mcp 원격 HTTP 진입 — Streamable HTTP transport (stateful 세션).
 *
 * 호스팅 remote MCP: 클라이언트(Claude/ChatGPT 등)가 mcp.loftbox.net 에 연결하고
 * `Authorization: Bearer <LoftBox API key>` 로 인증한다. 키로 MCP 서버를 생성하므로 키
 * 검증은 다운스트림 loftbox-api 가 수행(이 RS 는 pass-through, AS 아님).
 *
 * MCP 는 initialize→이후 요청의 stateful 생명주기라 세션을 유지한다: initialize POST 시
 * 세션 생성(mcp-session-id 발급) + 그 키로 server 생성, 후속 요청은 session-id 로 재사용.
 * 세션은 apiKey 에 바인딩 — 후속 요청의 Bearer 가 다르면 거부(session-id 탈취 방어).
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
  logStderr,
  SERVER_NAME,
  SERVER_VERSION,
} from "./server.js";

const PORT = Number(process.env.LOFTBOX_MCP_PORT ?? "3100");
const HOST = process.env.LOFTBOX_MCP_HOST ?? "127.0.0.1";
const MCP_PATH = "/mcp";
const MAX_BODY_BYTES = 1_000_000;
const SESSION_IDLE_MS = 30 * 60 * 1000; // 30분 유휴 후 정리
const MAX_SESSIONS = 2000; // 세션맵 상한(메모리 DoS 백스톱)
const DEFAULT_BASE_URL = "https://api.loftbox.net";

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

interface Session {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  apiKey: string;
  lastUsed: number;
}

const sessions = new Map<string, Session>();

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
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function jsonRpcError(code: number, message: string): unknown {
  return { jsonrpc: "2.0", error: { code, message }, id: null };
}

function dropSession(sid: string): void {
  const s = sessions.get(sid);
  if (!s) return;
  sessions.delete(sid);
  void s.transport.close();
  void s.server.close();
}

async function handleMcp(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const apiKey = extractBearer(req);
  if (!apiKey) {
    res.setHeader("WWW-Authenticate", 'Bearer realm="loftbox-mcp"');
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
    const existing = sessions.get(sid);
    if (!existing) {
      sendJson(
        res,
        404,
        jsonRpcError(-32001, "세션을 찾을 수 없습니다(만료/무효)"),
      );
      return;
    }
    // 세션↔apiKey 바인딩: session-id 만으로는 부족 — Bearer 도 일치해야 함.
    if (existing.apiKey !== apiKey) {
      sendJson(res, 403, jsonRpcError(-32001, "세션 인증 불일치"));
      return;
    }
    existing.lastUsed = Date.now();
    transport = existing.transport;
  } else if (req.method === "POST" && isInitializeRequest(body)) {
    if (sessions.size >= MAX_SESSIONS) {
      sendJson(
        res,
        503,
        jsonRpcError(-32000, "세션 한도 초과 — 잠시 후 재시도"),
      );
      return;
    }
    const baseUrl = resolvedBaseUrl();
    // 키 선검증: 잘못된 키로 세션 생성 차단(메모리 DoS·미인증 상태 방지).
    if (!(await validateApiKey(apiKey, baseUrl))) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="loftbox-mcp"');
      sendJson(res, 401, jsonRpcError(-32001, "API 키가 유효하지 않습니다"));
      return;
    }
    const server = createMcpServer({ apiKey, baseUrl });
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (newSid: string) => {
        sessions.set(newSid, {
          transport,
          server,
          apiKey,
          lastUsed: Date.now(),
        });
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) dropSession(transport.sessionId);
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

  await transport.handleRequest(req, res, body);
}

// 유휴 세션 주기 정리(메모리 누수 방지).
const sweep = setInterval(
  () => {
    const now = Date.now();
    for (const [sid, s] of sessions) {
      if (now - s.lastUsed > SESSION_IDLE_MS) dropSession(sid);
    }
  },
  5 * 60 * 1000,
);
sweep.unref();

export function buildHttpServer(): Server {
  return createHttpServer((req, res) => {
    const path = (req.url ?? "").split("?")[0];
    if (path === "/health") {
      sendJson(res, 200, {
        status: "ok",
        server: SERVER_NAME,
        version: SERVER_VERSION,
      });
      return;
    }
    if (path === MCP_PATH) {
      handleMcp(req, res).catch((e) => {
        logStderr(`MCP 요청 처리 오류: ${(e as Error)?.stack ?? String(e)}`);
        if (!res.headersSent)
          sendJson(res, 500, jsonRpcError(-32603, "내부 오류"));
      });
      return;
    }
    sendJson(res, 404, { error: "not found" });
  });
}

function isMain(): boolean {
  const entry = process.argv[1];
  return !!entry && import.meta.url === pathToFileURL(entry).href;
}

if (isMain()) {
  buildHttpServer().listen(PORT, HOST, () => {
    logStderr(
      `${SERVER_NAME} v${SERVER_VERSION} remote MCP listening on http://${HOST}:${PORT}${MCP_PATH}`,
    );
  });
}
