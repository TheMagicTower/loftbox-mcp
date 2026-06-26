import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { z } from "zod";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { LoftBoxApi, ApiError } from "../src/api.js";
import { TOOLS, guardMessage, guardPage } from "../src/tools.js";
import { invokeTool, describeError, createServer } from "../src/server.js";

type Handler = (req: Request) => Response | Promise<Response>;

function makeApi(handler: Handler): { api: LoftBoxApi; calls: Request[] } {
  const calls: Request[] = [];
  const fetchImpl = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const req = new Request(
      typeof input === "string" ? input : input.toString(),
      init,
    );
    calls.push(req);
    return handler(req);
  }) as unknown as typeof fetch;
  const api = new LoftBoxApi({
    apiKey: "lb_test",
    baseUrl: "https://api.test",
    fetch: fetchImpl,
  });
  return { api, calls };
}

function json(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function tool(name: string) {
  const t = TOOLS.find((x) => x.name === name);
  assert.ok(t, `tool ${name} 없음`);
  return t!;
}

/** 단일 호출의 Request 를 캡처하고 결과를 반환하는 헬퍼. */
async function callOnce(
  name: string,
  args: Record<string, unknown>,
  resp: (req: Request) => Response | Promise<Response>,
): Promise<{ req: Request; result: any }> {
  const { api, calls } = makeApi(resp);
  const result = await tool(name).handler(api, args);
  assert.equal(calls.length, 1, `${name} 는 정확히 1회 호출해야 함`);
  return { req: calls[0]!, result };
}

describe("레지스트리 무결성", () => {
  it("툴 이름이 유일하다", () => {
    const names = TOOLS.map((t) => t.name);
    assert.equal(new Set(names).size, names.length);
  });

  it("모든 inputSchema 가 루트 object 로 변환된다", () => {
    for (const t of TOOLS) {
      const schema = z.object(t.inputSchema);
      assert.equal(
        schema._def.typeName,
        "ZodObject",
        `${t.name} 루트 비object`,
      );
      assert.doesNotThrow(() => schema.safeParse({}));
    }
  });

  it("모든 툴에 openWorldHint 와 title/description 이 있다", () => {
    for (const t of TOOLS) {
      assert.equal(t.annotations.openWorldHint, true, `${t.name}`);
      assert.ok(t.title.length > 0);
      assert.ok(t.description.length > 0);
    }
  });

  it("read-only 툴은 destructiveHint 가 켜지지 않는다", () => {
    for (const t of TOOLS) {
      if (t.annotations.readOnlyHint) {
        assert.notEqual(t.annotations.destructiveHint, true, `${t.name}`);
      }
    }
  });

  it("비가역 툴은 destructiveHint 가 켜져 있다", () => {
    const mustDestroy = [
      "message_send",
      "message_approve",
      "message_reject",
      "suppression_add",
      "suppression_remove",
      "approval_policy_create",
    ];
    for (const name of mustDestroy) {
      assert.equal(tool(name).annotations.destructiveHint, true, name);
    }
  });

  it("webhook_create 는 1차 스코프에서 제외되었다(secret 유출 방지)", () => {
    assert.equal(
      TOOLS.find((t) => t.name === "webhook_create"),
      undefined,
    );
  });
});

describe("MCP 통합 (in-process)", () => {
  it("tools/list 가 모든 툴을 루트 object 스키마로 노출한다", async () => {
    const server = createServer({
      apiKey: "lb_test",
      fetch: (async () => json({})) as unknown as typeof fetch,
    });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "test", version: "0" });
    await Promise.all([client.connect(clientT), server.connect(serverT)]);
    const { tools } = await client.listTools();
    assert.equal(tools.length, TOOLS.length);
    for (const t of tools) {
      assert.equal((t.inputSchema as any).type, "object", `${t.name}`);
      assert.ok(t.annotations, `${t.name} annotations 없음`);
    }
    assert.ok(tools.find((t) => t.name === "approval_queue_list"));
    await client.close();
  });

  it("tools/call 성공이 text content 로 온다", async () => {
    const server = createServer({
      apiKey: "lb_test",
      fetch: (async () =>
        json({ id: "ag_1", name: "Bot" })) as unknown as typeof fetch,
    });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "test", version: "0" });
    await Promise.all([client.connect(clientT), server.connect(serverT)]);
    const res: any = await client.callTool({
      name: "agent_get",
      arguments: { agent_id: "ag_1" },
    });
    assert.equal(res.isError, undefined);
    assert.equal(JSON.parse(res.content[0].text).id, "ag_1");
    await client.close();
  });
});

describe("요청 shaping — agents/mailboxes", () => {
  it("agent_create — POST, snake_case·null 채움", async () => {
    const { req, result } = await callOnce(
      "agent_create",
      { name: "Bot", slug: "bot" },
      async (r) => {
        assert.equal(r.method, "POST");
        assert.ok(r.url.endsWith("/v1/agents"));
        assert.equal(r.headers.get("authorization"), "Bearer lb_test");
        const b = await r.json();
        assert.equal(b.name, "Bot");
        assert.equal(b.description, null);
        return json({ id: "ag_1" }, 201);
      },
    );
    assert.equal(result.id, "ag_1");
    assert.ok(req);
  });

  it("agent_get — GET path 인코딩", async () => {
    await callOnce("agent_get", { agent_id: "ag/1" }, async (r) => {
      assert.ok(new URL(r.url).pathname.endsWith("/v1/agents/ag%2F1"));
      return json({ id: "ag/1" });
    });
  });

  it("agent_list — 페이지 정규화·undefined query 누락", async () => {
    const { result } = await callOnce("agent_list", { limit: 5 }, async (r) => {
      const u = new URL(r.url);
      assert.equal(u.searchParams.has("cursor"), false);
      assert.equal(u.searchParams.get("limit"), "5");
      return json({ data: [{ id: "ag_1" }], next_cursor: "c2" });
    });
    assert.equal(result.data.length, 1);
    assert.equal(result.next_cursor, "c2");
  });

  it("agent_list — bare array 응답 수용", async () => {
    const { result } = await callOnce("agent_list", {}, async () =>
      json([{ id: "ag_1" }]),
    );
    assert.equal(result.next_cursor, null);
  });

  it("mailbox_create — POST 경로·본문", async () => {
    await callOnce(
      "mailbox_create",
      { agent_id: "ag_1", local_part: "hi" },
      async (r) => {
        assert.equal(r.method, "POST");
        assert.ok(r.url.endsWith("/v1/agents/ag_1/mailboxes"));
        const b = await r.json();
        assert.equal(b.local_part, "hi");
        assert.equal(b.domain_id, null);
        return json({ id: "mb_1" }, 201);
      },
    );
  });

  it("mailbox_list — GET 경로", async () => {
    const { result } = await callOnce(
      "mailbox_list",
      { agent_id: "ag_1" },
      async (r) => {
        assert.ok(r.url.endsWith("/v1/agents/ag_1/mailboxes"));
        return json({ data: [{ id: "mb_1" }] });
      },
    );
    assert.equal(result.data.length, 1);
  });

  it("inbox_list — GET 경로·페이지", async () => {
    const { result } = await callOnce(
      "inbox_list",
      { mailbox_id: "mb_1", limit: 2 },
      async (r) => {
        const u = new URL(r.url);
        assert.ok(u.pathname.endsWith("/v1/mailboxes/mb_1/inbox"));
        assert.equal(u.searchParams.get("limit"), "2");
        return json({ data: [], next_cursor: null });
      },
    );
    assert.equal(result.data.length, 0);
  });

  it("inbox_ack — POST message_ids", async () => {
    await callOnce(
      "inbox_ack",
      { mailbox_id: "mb_1", message_ids: ["m1", "m2"] },
      async (r) => {
        assert.equal(r.method, "POST");
        assert.ok(r.url.endsWith("/v1/mailboxes/mb_1/inbox/ack"));
        const b = await r.json();
        assert.deepEqual(b.message_ids, ["m1", "m2"]);
        return json({ acked: 2 });
      },
    );
  });
});

describe("요청 shaping — messages/labels", () => {
  it("message_send — Idempotency-Key 헤더 + replay 캡처", async () => {
    const { result } = await callOnce(
      "message_send",
      {
        mailbox_id: "mb_1",
        to: ["a@b.com"],
        subject: "hi",
        body_text: "b",
        send_at: "2030-01-01T00:00:00Z",
        idempotency_key: "key-1",
      },
      async (r) => {
        assert.equal(r.method, "POST");
        assert.equal(r.headers.get("idempotency-key"), "key-1");
        const b = await r.json();
        assert.deepEqual(b.to, ["a@b.com"]);
        assert.equal(b.cc.length, 0);
        assert.equal(b.send_at, "2030-01-01T00:00:00Z");
        return json({ id: "msg_1", status: "pending_approval" }, 201, {
          "Idempotent-Replayed": "true",
        });
      },
    );
    assert.equal(result.status, "pending_approval");
    assert.equal(result.idempotent_replayed, true);
  });

  it("message_send — 멱등키 없으면 헤더 없고 replay=false", async () => {
    const { result } = await callOnce(
      "message_send",
      { mailbox_id: "mb_1", to: ["a@b.com"], subject: "hi" },
      async (r) => {
        assert.equal(r.headers.get("idempotency-key"), null);
        return json({ id: "msg_2", status: "queued" }, 201);
      },
    );
    assert.equal(result.idempotent_replayed, false);
  });

  it("message_get — GET", async () => {
    await callOnce("message_get", { message_id: "m1" }, async (r) => {
      assert.ok(r.url.endsWith("/v1/messages/m1"));
      return json({ id: "m1" });
    });
  });

  it("message_list — q/label/status 전달, undefined 누락", async () => {
    await callOnce(
      "message_list",
      { q: "invoice", label: "vip", status: "sent" },
      async (r) => {
        const u = new URL(r.url);
        assert.equal(u.searchParams.get("q"), "invoice");
        assert.equal(u.searchParams.get("label"), "vip");
        assert.equal(u.searchParams.get("status"), "sent");
        assert.equal(u.searchParams.has("mailbox_id"), false);
        return json({ data: [], next_cursor: null });
      },
    );
  });

  it("label_add — POST labels 배열", async () => {
    await callOnce(
      "label_add",
      { message_id: "m1", labels: ["vip", "urgent"] },
      async (r) => {
        assert.equal(r.method, "POST");
        assert.ok(r.url.endsWith("/v1/messages/m1/labels"));
        const b = await r.json();
        assert.deepEqual(b.labels, ["vip", "urgent"]);
        return json({ id: "m1", labels: ["vip", "urgent"] });
      },
    );
  });

  it("label_remove — DELETE 경로 특수문자 인코딩", async () => {
    await callOnce(
      "label_remove",
      { message_id: "m1", label: "needs review/urgent" },
      async (r) => {
        const u = new URL(r.url);
        assert.ok(u.pathname.endsWith("/labels/needs%20review%2Furgent"));
        assert.equal(r.method, "DELETE");
        return json({ id: "m1", labels: [] });
      },
    );
  });
});

describe("요청 shaping — HITL", () => {
  it("approval_queue_list — status=pending_approval&direction=outgoing 고정", async () => {
    const { result } = await callOnce("approval_queue_list", {}, async (r) => {
      const u = new URL(r.url);
      assert.ok(u.pathname.endsWith("/v1/messages"));
      assert.equal(u.searchParams.get("status"), "pending_approval");
      assert.equal(u.searchParams.get("direction"), "outgoing");
      return json({ data: [{ id: "m1" }] });
    });
    assert.equal(result.data.length, 1);
  });

  it("message_approve — POST reason", async () => {
    await callOnce(
      "message_approve",
      { message_id: "m1", reason: "ok" },
      async (r) => {
        assert.equal(r.method, "POST");
        assert.ok(r.url.endsWith("/v1/messages/m1/approve"));
        assert.equal((await r.json()).reason, "ok");
        return json({ id: "m1", status: "approved" });
      },
    );
  });

  it("message_reject — POST reason", async () => {
    await callOnce(
      "message_reject",
      { message_id: "m1", reason: "no" },
      async (r) => {
        assert.ok(r.url.endsWith("/v1/messages/m1/reject"));
        assert.equal((await r.json()).reason, "no");
        return json({ id: "m1", status: "rejected" });
      },
    );
  });

  it("approval_policy_list — enabled query", async () => {
    await callOnce("approval_policy_list", { enabled: true }, async (r) => {
      assert.equal(new URL(r.url).searchParams.get("enabled"), "true");
      return json({ data: [] });
    });
  });

  it("approval_policy_create — POST 필수+옵션", async () => {
    await callOnce(
      "approval_policy_create",
      { action: "block", name: "p", scope_type: "org", priority: 5 },
      async (r) => {
        assert.equal(r.method, "POST");
        assert.ok(r.url.endsWith("/v1/approval-policies"));
        const b = await r.json();
        assert.equal(b.action, "block");
        assert.equal(b.scope_type, "org");
        assert.equal(b.priority, 5);
        assert.equal(b.classification, null);
        return json({ id: "pol_1" }, 201);
      },
    );
  });
});

describe("요청 shaping — threads/domains/suppressions/attachments/events", () => {
  it("thread_list — query", async () => {
    await callOnce("thread_list", { mailbox_id: "mb_1" }, async (r) => {
      assert.equal(new URL(r.url).searchParams.get("mailbox_id"), "mb_1");
      return json({ data: [] });
    });
  });

  it("thread_messages — GET 경로", async () => {
    await callOnce("thread_messages", { thread_id: "t1" }, async (r) => {
      assert.ok(r.url.endsWith("/v1/threads/t1/messages"));
      return json({ data: [] });
    });
  });

  it("domain_create — POST", async () => {
    await callOnce("domain_create", { domain: "x.com" }, async (r) => {
      assert.equal(r.method, "POST");
      assert.equal((await r.json()).domain, "x.com");
      return json({ id: "dom_1" }, 201);
    });
  });

  it("domain_list — GET 페이지", async () => {
    const { result } = await callOnce("domain_list", {}, async (r) => {
      assert.ok(r.url.endsWith("/v1/domains"));
      return json([{ id: "dom_1" }]);
    });
    assert.equal(result.data.length, 1);
  });

  it("domain_status — GET status", async () => {
    const { result } = await callOnce(
      "domain_status",
      { domain_id: "dom_1" },
      async (r) => {
        assert.ok(r.url.endsWith("/v1/domains/dom_1/status"));
        return json({ status: "pending", next_actions: ["TXT"] });
      },
    );
    assert.equal(result.status, "pending");
  });

  it("suppression_list — query", async () => {
    await callOnce("suppression_list", { limit: 10 }, async (r) => {
      assert.equal(new URL(r.url).searchParams.get("limit"), "10");
      return json({ data: [] });
    });
  });

  it("suppression_add — POST address", async () => {
    await callOnce("suppression_add", { address: "a@b.com" }, async (r) => {
      assert.equal(r.method, "POST");
      assert.equal((await r.json()).address, "a@b.com");
      return json({ id: "sup_1" }, 201);
    });
  });

  it("suppression_remove — DELETE 후 확인 객체", async () => {
    const { result } = await callOnce(
      "suppression_remove",
      { suppression_id: "sup_1" },
      async (r) => {
        assert.equal(r.method, "DELETE");
        assert.ok(r.url.endsWith("/v1/suppressions/sup_1"));
        return new Response(null, { status: 204 });
      },
    );
    assert.equal(result.deleted, true);
  });

  it("attachment_list — GET 경로", async () => {
    await callOnce("attachment_list", { message_id: "m1" }, async (r) => {
      assert.ok(r.url.endsWith("/v1/messages/m1/attachments"));
      return json({ data: [] });
    });
  });

  it("attachment_url — GET url", async () => {
    await callOnce("attachment_url", { attachment_id: "at_1" }, async (r) => {
      assert.ok(r.url.endsWith("/v1/attachments/at_1/url"));
      return json({ url: "https://signed" });
    });
  });

  it("event_list — query 필터", async () => {
    await callOnce(
      "event_list",
      { agent_id: "ag_1", event_type: "message.sent" },
      async (r) => {
        const u = new URL(r.url);
        assert.equal(u.searchParams.get("agent_id"), "ag_1");
        assert.equal(u.searchParams.get("event_type"), "message.sent");
        return json({ data: [] });
      },
    );
  });
});

describe("오류 매핑", () => {
  it("api.request — ApiError(status/retryAfter) throw", async () => {
    const { api } = makeApi(async () =>
      json({ error: { message: "rate limited", retry_after: 7 } }, 429),
    );
    await assert.rejects(
      () => api.request("GET", "/v1/messages"),
      (e: unknown) => {
        assert.ok(e instanceof ApiError);
        assert.equal((e as ApiError).status, 429);
        assert.equal((e as ApiError).retryAfterSecs, 7);
        return true;
      },
    );
  });

  it("api.request — 타임아웃은 AbortError → 타임아웃 메시지", async () => {
    const api = new LoftBoxApi({
      apiKey: "lb_test",
      baseUrl: "https://api.test",
      timeoutMs: 5,
      fetch: (async (_u: string, init: RequestInit) =>
        new Promise((_res, rej) => {
          init.signal?.addEventListener("abort", () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            rej(err);
          });
        })) as unknown as typeof fetch,
    });
    await assert.rejects(
      () => api.request("GET", "/v1/messages"),
      (e: unknown) => {
        assert.ok(e instanceof ApiError);
        assert.match((e as ApiError).message, /타임아웃/);
        return true;
      },
    );
  });

  it("invokeTool — 403 은 단정 없이 권한 안내 isError", async () => {
    const { api } = makeApi(async () =>
      json({ error: { message: "forbidden" } }, 403),
    );
    const r = await invokeTool(api, tool("approval_policy_create"), {
      action: "block",
      name: "p",
      scope_type: "org",
    });
    assert.equal(r.isError, true);
    assert.match(r.content[0]!.text, /권한/);
  });

  it("invokeTool — 성공은 text JSON content", async () => {
    const { api } = makeApi(async () => json({ id: "ag_1", name: "Bot" }));
    const r = await invokeTool(api, tool("agent_get"), { agent_id: "ag_1" });
    assert.notEqual(r.isError, true);
    assert.deepEqual(JSON.parse(r.content[0]!.text), {
      id: "ag_1",
      name: "Bot",
    });
  });

  it("invokeTool — 204/undefined 결과는 ok:true 로 포장", async () => {
    const { api } = makeApi(async () => new Response(null, { status: 204 }));
    const r = await invokeTool(api, tool("inbox_ack"), {
      mailbox_id: "mb_1",
      message_ids: ["m1"],
    });
    assert.notEqual(r.isError, true);
    assert.deepEqual(JSON.parse(r.content[0]!.text), { ok: true });
  });

  it("describeError — 401 안내", () => {
    assert.match(describeError(new ApiError(401, "nope")), /API 키/);
  });
});

describe("인바운드 인젝션 가드 (#369/#370)", () => {
  it("guardMessage — 고위험은 _safety_warning 주입(제목 보존)", () => {
    const out: any = guardMessage(
      {
        id: "m1",
        subject: "hi",
        injection_score: 0.92,
        injection_categories: ["instruction_override"],
      },
      0.7,
      false,
    );
    assert.match(out._safety_warning, /신뢰불가/);
    assert.match(out._safety_warning, /instruction_override/);
    assert.equal(out.subject, "hi");
  });

  it("guardMessage — 저위험/미채점/발신은 동일 객체 무변경", () => {
    const low = { id: "m1", injection_score: 0.1 };
    assert.equal(guardMessage(low, 0.7, false), low);
    const none = { id: "m2" };
    assert.equal(guardMessage(none, 0.7, false), none);
  });

  it("guardMessage — strict 모드는 제목/본문 차단", () => {
    const out: any = guardMessage(
      {
        id: "m1",
        subject: "secret",
        body_text: "x",
        body_html: "<b>x</b>",
        injection_score: 0.9,
      },
      0.7,
      true,
    );
    assert.equal(out.subject, "[차단됨: 인젝션 위험]");
    assert.equal(out.body_text, null);
    assert.equal(out.body_html, null);
    assert.match(out._safety_warning, /위험/);
  });

  it("guardPage — 각 메시지에 적용, next_cursor 보존", () => {
    const p = guardPage(
      {
        data: [
          {
            id: "m1",
            injection_score: 0.95,
            injection_categories: ["role_hijack"],
          },
          { id: "m2", injection_score: 0.0 },
        ],
        next_cursor: "c",
      },
      0.7,
      false,
    );
    assert.match((p.data[0] as any)._safety_warning, /role_hijack/);
    assert.equal((p.data[1] as any)._safety_warning, undefined);
    assert.equal(p.next_cursor, "c");
  });

  it("inbox_list — 고위험 수신메일에 _safety_warning 부착", async () => {
    const { result } = await callOnce(
      "inbox_list",
      { mailbox_id: "mb_1" },
      async () =>
        json({
          data: [
            {
              id: "in_1",
              subject: "hi",
              injection_score: 0.9,
              injection_categories: ["tool_injection"],
            },
          ],
          next_cursor: null,
        }),
    );
    assert.match(result.data[0]._safety_warning, /tool_injection/);
  });
});
