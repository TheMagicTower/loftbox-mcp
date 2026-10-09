import assert from "node:assert/strict";
import { describe, it, afterEach } from "node:test";
import type { AddressInfo } from "node:net";
import { createServer as createHttpServer, type Server } from "node:http";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { buildHttpServer } from "../src/http.js";

// 로컬 루프백 테스트 — 샌드박스 프록시 경유 금지(결정적 실행).
for (const k of ["NO_PROXY", "no_proxy"]) {
  const cur = process.env[k] ?? "";
  if (!cur.includes("127.0.0.1")) {
    process.env[k] = cur ? `${cur},127.0.0.1,localhost` : "127.0.0.1,localhost";
  }
}

async function startServer(): Promise<{
  port: number;
  close: () => Promise<void>;
}> {
  const server = buildHttpServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    port: addr.port,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** loftbox-api 목 — GET /v1 에 지정 status 응답(키 선검증 대상). */
async function startMockApi(
  status: number,
): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createHttpServer((_req, res) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: status < 400 }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("remote MCP HTTP transport", () => {
  afterEach(() => {
    delete process.env.LOFTBOX_BASE_URL;
    delete process.env.LOFTBOX_MCP_READ_ONLY;
  });

  it("유효 키: initialize → tools/list (stateful 세션)", async () => {
    const mock = await startMockApi(200); // 키 검증 통과
    process.env.LOFTBOX_BASE_URL = mock.url;
    const { port, close } = await startServer();
    try {
      const transport = new StreamableHTTPClientTransport(
        new URL(`http://127.0.0.1:${port}/mcp`),
        { requestInit: { headers: { Authorization: "Bearer lb_test_valid" } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      const tools = await client.listTools();
      assert.ok(tools.tools.length > 0, "tools 가 노출되어야 한다");
      await client.close();
    } finally {
      await close();
      await mock.close();
    }
  });

  it("무효 키: initialize → 거부(세션 미생성)", async () => {
    const mock = await startMockApi(401); // 키 검증 실패
    process.env.LOFTBOX_BASE_URL = mock.url;
    const { port, close } = await startServer();
    try {
      const transport = new StreamableHTTPClientTransport(
        new URL(`http://127.0.0.1:${port}/mcp`),
        { requestInit: { headers: { Authorization: "Bearer lb_test_bad" } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await assert.rejects(
        () => client.connect(transport),
        "무효 키는 connect 실패",
      );
    } finally {
      await close();
      await mock.close();
    }
  });

  it("Bearer 없으면 401", async () => {
    const { port, close } = await startServer();
    try {
      const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "initialize",
          id: 1,
          params: {},
        }),
      });
      assert.equal(res.status, 401);
      assert.ok(res.headers.get("www-authenticate")?.includes("Bearer"));
    } finally {
      await close();
    }
  });

  it("/health → 200", async () => {
    const { port, close } = await startServer();
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      assert.equal(res.status, 200);
      const body = (await res.json()) as { status: string };
      assert.equal(body.status, "ok");
    } finally {
      await close();
    }
  });

  it("LOFTBOX_MCP_READ_ONLY=true — HTTP 실전송에서 관리 쓰기 미노출", async () => {
    const mock = await startMockApi(200);
    process.env.LOFTBOX_BASE_URL = mock.url;
    process.env.LOFTBOX_MCP_READ_ONLY = "true";
    const { port, close } = await startServer();
    try {
      const transport = new StreamableHTTPClientTransport(
        new URL(`http://127.0.0.1:${port}/mcp`),
        { requestInit: { headers: { Authorization: "Bearer [REDACTED]" } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        const names = tools.map((t) => t.name);
        assert.ok(names.includes("auth_context"), "읽기 노출");
        assert.ok(names.includes("marketing_capability"), "읽기 노출");
        for (const w of [
          "api_key_revoke",
          "domain_verify",
          "domain_remove",
          "marketing_audience_create",
          "marketing_sender_profile_create",
          "marketing_sender_profile_disable",
          "newsletter_subscription_sync",
        ]) {
          assert.ok(!names.includes(w), `HTTP read-only 에서 ${w} 숨김 필요`);
        }
        // 숨김 쓰기 수동 지명 호출도 거부(API 호출 없음, isError).
        const res: any = await client.callTool({
          name: "newsletter_subscription_sync",
          arguments: {
            audience_public_id: "aud_1",
            email_hash: "a".repeat(64),
            email: "user@example.com",
            source: "homepage",
            source_revision: 1,
            expected_version: 0,
            action: "unsubscribe",
            confirmed: true,
          },
        });
        assert.equal(res.isError, true, "숨김 쓰기는 isError");
      } finally {
        await client.close();
      }
    } finally {
      await close();
      await mock.close();
    }
  });
});
