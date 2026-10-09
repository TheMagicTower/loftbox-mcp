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
import { MANAGEMENT_TOOLS, SyncConflictError } from "./management-tools.js";

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

/** ApiError 를 사람이 읽는 MCP 오류 메시지로 변환.
 *
 * 403 은 툴의 `requiredScopes` 를 알면 그 fine scope 를 지목한다(막연한
 * admin 권유 금지). 모르면(기존 툴) 단정 없이 권한 부족 가능성을 안내한다.
 * 실제 인가는 백엔드 scope/capability 게이트가 수행한다. */
export function describeError(
  e: unknown,
  tool?: Pick<ToolDef, "name" | "requiredScopes">,
): string {
  if (e instanceof ApiError) {
    const parts = [`LoftBox API 오류 (HTTP ${e.status}): ${e.message}`];
    if (e.status === 401) {
      parts.push("API 키가 유효하지 않습니다 (LOFTBOX_API_KEY 확인).");
    } else if (e.status === 403) {
      const scopes = tool?.requiredScopes ?? [];
      if (scopes.length > 0) {
        parts.push(
          `권한이 거부되었습니다. 이 툴('${tool!.name}')은 ` +
            `${scopes.map((s) => `'${s}'`).join(", ")} scope API 키가 필요합니다. ` +
            "최소권한 키로 재시도하세요(백엔드 scope 게이트가 최종 판정).",
        );
      } else {
        // 403 은 scope 부족·org 접근 거부·리소스 소유권·비활성 키 등
        // 여러 원인이 가능하다. 단정하지 않고 가능성을 안내한다(codex Major).
        parts.push(
          "권한이 거부되었습니다. 이 작업에 필요한 권한이 키에 없을 수 있습니다.",
        );
      }
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
    // 검증된 sync 충돌 스냅샷: text JSON + structuredContent 로 revision 보존.
    if (e instanceof SyncConflictError) {
      return {
        isError: true,
        content: [{ type: "text", text: e.message }],
        structuredContent: { status: e.status, ...e.snapshot },
      };
    }
    return {
      isError: true,
      content: [{ type: "text", text: describeError(e, tool) }],
    };
  }
}

export interface ServerConfig {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  /** 테스트용 커스텀 fetch. */
  fetch?: typeof fetch;
  /** true 면 readOnlyHint 툴만 등록(쓰기 툴은 SDK 에 미노출). */
  readOnly?: boolean;
  /** 허용 툴 이름 allowlist — 지정 시 해당 툴만 등록한다(OAuth scope 프로필용).
   *  readOnly 와 함께 지정되면 둘 다 만족하는 툴만 남는다. */
  allowedTools?: readonly string[];
}

/** OAuth scope 에 대응하는 툴 allowlist.
 *
 * - `loftbox.read` → readOnlyHint 툴만.
 * - `loftbox.manage` → 읽기에 더해 *신규 관리 툴(MANAGEMENT_TOOLS)의 쓰기*만
 *   추가한다. 기존 발송/승인/생성 등 레거시 쓰기는 포함하지 않는다.
 * - 서버 env `readOnly` 가 true 면 상한으로 적용되어 manage 도 읽기로 축소된다.
 * 실제 인가는 백엔드 scope 게이트가 수행한다. */
export function allowedToolsForScope(
  scope: readonly string[],
  readOnlyEnv: boolean,
): string[] {
  const read = allTools()
    .filter((t) => t.annotations.readOnlyHint === true)
    .map((t) => t.name);
  if (readOnlyEnv || !scope.includes("loftbox.manage")) return read;
  const mgmtWrites = MANAGEMENT_TOOLS.filter(
    (t) => t.annotations.readOnlyHint !== true,
  ).map((t) => t.name);
  return [...read, ...mgmtWrites];
}

/** 전체 툴 레지스트리(기존 admin 평면 + 관리 평면). */
export function allTools(): ToolDef[] {
  return [...TOOLS, ...MANAGEMENT_TOOLS];
}

/** `LOFTBOX_MCP_READ_ONLY=true` 명시 때만 true(기본 전체 등록 유지).
 *  설정은 서버 env/설정에서만 — 클라이언트 인자로 받지 않는다. */
export function isReadOnlyFromEnv(
  env: Record<string, string | undefined> = process.env,
): boolean {
  return (env.LOFTBOX_MCP_READ_ONLY ?? "").trim().toLowerCase() === "true";
}

/** 설정으로 MCP 서버 인스턴스를 만들고 툴을 등록한다(연결은 호출측).
 *  `readOnly` 면 annotation-read-only 툴만 등록 — 쓰기 툴은 수동 지명으로도
 *  호출 불가(SDK 미등록). */
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

  let tools = config.readOnly
    ? allTools().filter((t) => t.annotations.readOnlyHint === true)
    : allTools();
  if (config.allowedTools) {
    const allow = new Set(config.allowedTools);
    tools = tools.filter((t) => allow.has(t.name));
  }
  for (const tool of tools) {
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
