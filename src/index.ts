#!/usr/bin/env node
/** loftbox-mcp 실행 엔트리 (stdio transport).
 *
 * stdout 은 JSON-RPC 전용이다. 기동 메시지·env 오류·디버그는 전부 stderr 로만
 * 출력한다(codex Minor). 비정상 종료는 stderr 에 사유를 남기고 exit(1).
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  createServer,
  logStderr,
  SERVER_NAME,
  SERVER_VERSION,
} from "./server.js";

async function main(): Promise<void> {
  const apiKey = process.env.LOFTBOX_API_KEY;
  if (!apiKey) {
    logStderr(
      "환경변수 LOFTBOX_API_KEY 가 필요합니다. LoftBox API 키를 설정하세요.",
    );
    process.exit(1);
  }

  const baseUrl = process.env.LOFTBOX_BASE_URL;
  const timeoutRaw = process.env.LOFTBOX_TIMEOUT_MS;
  const timeoutMs = timeoutRaw ? Number(timeoutRaw) : undefined;
  if (
    timeoutRaw &&
    (!Number.isFinite(timeoutMs) || (timeoutMs as number) <= 0)
  ) {
    logStderr(`LOFTBOX_TIMEOUT_MS 값이 올바르지 않습니다: ${timeoutRaw}`);
    process.exit(1);
  }

  const server = createServer({ apiKey, baseUrl, timeoutMs });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logStderr(
    `${SERVER_NAME} v${SERVER_VERSION} 기동 (base=${baseUrl ?? "https://api.loftbox.net"}).`,
  );
}

main().catch((e) => {
  logStderr(`치명적 오류: ${(e as Error)?.stack ?? String(e)}`);
  process.exit(1);
});
