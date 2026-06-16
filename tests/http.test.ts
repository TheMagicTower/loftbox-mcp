import assert from "node:assert/strict";
import { describe, it, afterEach } from "node:test";
import type { AddressInfo } from "node:net";
import { createServer as createHttpServer, type Server } from "node:http";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { buildHttpServer } from "../src/http.js";

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
});
