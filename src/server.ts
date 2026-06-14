/** LoftBox MCP 서버 배선.
 *
 * 고수준 McpServer 를 사용해 tools capability 를 자동 선언하고(codex C2),
 * 각 툴의 zod inputSchema 를 루트 object JSON Schema 로 변환한다. 핸들러 결과는
 * text(JSON) content 로 포장하고, ApiError 는 isError 결과로 변환한다.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ApiError, LoftBoxApi } from "./api.js";
import { TOOLS } from "./tools.js";
import type { ToolDef } from "./tools.js";

export const SERVER_NAME = "loftbox-mcp";
export const SERVER_VERSION = "0.1.0";

/** stderr 로그 — stdout 은 JSON-RPC 전용이므로 오염시키지 않는다. */
export function logStderr(msg: string): void {
  process.stderr.write(`[loftbox-mcp] ${msg}\n`);
}

export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
  // MCP CallToolResult 가 추가 메타 키를 허용하므로 인덱스 시그니처를 둔다.
  [key: string]: unknown;
}

/** ApiError 를 사람이 읽는 MCP 오류 메시지로 변환. */
export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    const parts = [`LoftBox API 오류 (HTTP ${e.status}): ${e.message}`];
    if (e.status === 401) {
      parts.push("API 키가 유효하지 않습니다 (LOFTBOX_API_KEY 확인).");
    } else if (e.status === 403) {
      // 403 은 admin scope 부족·org 접근 거부·리소스 소유권·비활성 키 등
      // 여러 원인이 가능하다. 단정하지 않고 가능성을 안내한다(codex Major).
      parts.push(
        "권한이 거부되었습니다. 이 작업에 필요한 권한(예: admin scope) 또는 " +
          "해당 리소스 접근 권한이 키에 없을 수 있습니다.",
      );
    } else if (e.status === 429 && e.retryAfterSecs != null) {
      parts.push(`${e.retryAfterSecs}초 후 재시도하세요.`);
    }
    return parts.join(" ");
  }
  return `예기치 못한 오류: ${(e as Error)?.message ?? String(e)}`;
}

/** 툴 핸들러를 실행하고 MCP 결과(성공=text JSON, 실패=isError)로 포장. */
export async function invokeTool(
  api: LoftBoxApi,
  tool: ToolDef,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  try {
    const result = await tool.handler(api, args ?? {});
    // 204/빈 본문이면 result 가 undefined → JSON.stringify 가 undefined 를 내
    // text 가 빈 값이 되는 것을 막는다(codex Major). 성공 사실을 객체로 표현.
    const text =
      result === undefined
        ? JSON.stringify({ ok: true }, null, 2)
        : JSON.stringify(result, null, 2);
    return { content: [{ type: "text", text }] };
  } catch (e) {
    return {
      isError: true,
      content: [{ type: "text", text: describeError(e) }],
    };
  }
}

export interface ServerConfig {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  /** 테스트용 커스텀 fetch. */
  fetch?: typeof fetch;
}

/** 설정으로 MCP 서버 인스턴스를 만들고 모든 툴을 등록한다(연결은 호출측). */
export function createServer(config: ServerConfig): McpServer {
  const api = new LoftBoxApi({
    apiKey: config.apiKey,
    baseUrl: config.baseUrl,
    timeoutMs: config.timeoutMs,
    fetch: config.fetch,
  });

  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: { title: tool.title, ...tool.annotations },
      },
      async (args: Record<string, unknown>) => invokeTool(api, tool, args),
    );
  }

  return server;
}
