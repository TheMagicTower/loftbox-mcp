import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { z } from "zod";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { LoftBoxApi, ApiError } from "../src/api.js";
import { TOOLS } from "../src/tools.js";
import {
  MANAGEMENT_TOOLS,
  MAX_SAFE_INTEGER,
  pickSyncErrorBody,
  syncMalformedMessage,
} from "../src/management-tools.js";
import {
  invokeTool,
  describeError,
  createServer,
  allTools,
  isReadOnlyFromEnv,
} from "../src/server.js";

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

function mtool(name: string) {
  const t = MANAGEMENT_TOOLS.find((x) => x.name === name);
  assert.ok(t, `management tool ${name} 없음`);
  return t!;
}

async function callOnce(
  name: string,
  args: Record<string, unknown>,
  resp: (req: Request) => Response | Promise<Response>,
): Promise<{ req: Request; result: any }> {
  const { api, calls } = makeApi(resp);
  const result = await mtool(name).handler(api, args);
  assert.equal(calls.length, 1, `${name} 는 정확히 1회 호출해야 함`);
  return { req: calls[0]!, result };
}

async function linkedClient(
  serverFetch: Handler,
  readOnly = false,
): Promise<{
  client: Client;
  calls: Request[];
  close: () => Promise<void>;
}> {
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
    return serverFetch(req);
  }) as unknown as typeof fetch;
  const server = createServer({
    apiKey: "lb_test",
    fetch: fetchImpl,
    readOnly,
  });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([client.connect(clientT), server.connect(serverT)]);
  // 양쪽을 모두 닫아야 open handle 없이 종료된다. 호출 테스트는 t.after 로 등록.
  const close = async () => {
    await client.close().catch(() => {});
    await server.close().catch(() => {});
  };
  return { client, calls, close };
}

const HASH = "a".repeat(64);
const CONSENT = {
  proof_source: "homepage-form",
  version: "v3",
  text: "뉴스레터 수신에 동의합니다.",
  collected_at: "2026-10-01T00:00:00Z",
};

describe("관리 툴 레지스트리 무결성", () => {
  it("전체 이름이 유일하다(기존+관리)", () => {
    const names = allTools().map((t) => t.name);
    assert.equal(new Set(names).size, names.length);
    assert.equal(allTools().length, TOOLS.length + MANAGEMENT_TOOLS.length);
  });

  it("모든 inputSchema 가 루트 object 로 변환된다", () => {
    for (const t of MANAGEMENT_TOOLS) {
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
    for (const t of MANAGEMENT_TOOLS) {
      assert.equal(t.annotations.openWorldHint, true, `${t.name}`);
      assert.ok(t.title.length > 0);
      assert.ok(t.description.length > 0);
    }
  });

  it("읽기 툴은 readOnlyHint, 변경 툴은 confirmed 리터럴", () => {
    const reads = [
      "auth_context",
      "marketing_capability",
      "api_key_list",
      "domain_get",
      "domain_dns_records",
      "marketing_audience_list",
      "marketing_audience_get",
      "marketing_sender_profile_list",
      "marketing_sender_profile_get",
      "newsletter_subscription_get",
    ];
    const writes = [
      "api_key_revoke",
      "domain_verify",
      "domain_remove",
      "marketing_audience_create",
      "marketing_sender_profile_create",
      "marketing_sender_profile_disable",
      "newsletter_subscription_sync",
    ];
    assert.deepEqual(
      new Set(MANAGEMENT_TOOLS.map((t) => t.name)),
      new Set([...reads, ...writes]),
    );
    for (const name of reads) {
      const t = mtool(name);
      assert.equal(t.annotations.readOnlyHint, true, `${name} readOnly`);
      assert.notEqual(t.annotations.destructiveHint, true, name);
    }
    for (const name of writes) {
      const t = mtool(name);
      assert.notEqual(t.annotations.readOnlyHint, true, `${name} 쓰기 표시`);
      const shape = t.inputSchema as Record<string, z.ZodTypeAny>;
      assert.ok(shape.confirmed, `${name} confirmed 스키마 필요`);
      assert.equal(
        (shape.confirmed as z.ZodLiteral<boolean>)._def.typeName,
        "ZodLiteral",
        `${name} confirmed 는 리터럴`,
      );
    }
    // 파괴적 표시: 폐기·제거·one-way 비활성화.
    for (const name of [
      "api_key_revoke",
      "domain_remove",
      "marketing_sender_profile_disable",
    ]) {
      assert.equal(mtool(name).annotations.destructiveHint, true, name);
    }
    // domain_verify 는 readOnly 아님(검증 시도·persist).
    assert.equal(mtool("domain_verify").annotations.readOnlyHint, false);
  });

  it("신규 툴 설명에 필요 scope 노출(auth_context 는 인증만)", () => {
    for (const t of MANAGEMENT_TOOLS) {
      if (t.name === "auth_context") {
        assert.match(t.description, /별도 scope 불필요/);
        continue;
      }
      assert.ok(
        (t.requiredScopes ?? []).length > 0,
        `${t.name} requiredScopes 필요`,
      );
      for (const s of t.requiredScopes!) {
        assert.ok(
          t.description.includes(`'${s}'`),
          `${t.name} 설명에 '${s}' 노출 필요`,
        );
      }
    }
  });

  it("금지 표면 없음: 키 발급·raw HTTP·발송/예약/테스트발송·평문 자격", () => {
    const names = MANAGEMENT_TOOLS.map((t) => t.name);
    for (const banned of [
      "api_key_create",
      "api_key_issue",
      "key_issue",
      "raw_http",
      "http_request",
      "marketing_send",
      "campaign_send",
      "campaign_schedule",
      "test_send",
      "message_send",
    ]) {
      assert.ok(!names.includes(banned), `${banned} 금지`);
    }
    for (const t of MANAGEMENT_TOOLS) {
      const shape = t.inputSchema as Record<string, unknown>;
      assert.ok(!("api_key" in shape), `${t.name} 평문 키 입력 금지`);
      assert.ok(!("token" in shape), `${t.name} 토큰 입력 금지`);
    }
  });
});

describe("MCP 통합 — 관리 툴 list/call", () => {
  it("tools/list 에 관리 툴이 루트 object 스키마로 노출된다", async (t) => {
    const { client, calls, close } = await linkedClient(async () => json({}));
    t.after(() => close());
    const { tools } = await client.listTools();
    assert.equal(tools.length, allTools().length);
    for (const name of [
      "auth_context",
      "marketing_capability",
      "newsletter_subscription_sync",
    ]) {
      const tool = tools.find((x) => x.name === name);
      assert.ok(tool, `${name} 노출 필요`);
      assert.equal((tool!.inputSchema as any).type, "object", name);
      assert.ok(tool!.annotations, `${name} annotations 없음`);
    }
    assert.equal(calls.length, 0, "list 는 API 호출 없음");
  });

  it("tools/call — auth_context GET", async (t) => {
    const { client, calls, close } = await linkedClient(async (r) => {
      assert.equal(r.method, "GET");
      assert.ok(r.url.endsWith("/v1/auth/context"));
      return json({ organization: { slug: "acme" } });
    });
    t.after(() => close());
    const res: any = await client.callTool({
      name: "auth_context",
      arguments: {},
    });
    assert.equal(res.isError, undefined);
    assert.equal(JSON.parse(res.content[0].text).organization.slug, "acme");
    assert.equal(calls.length, 1);
  });

  it("tools/call — marketing_capability GET", async (t) => {
    const { client, calls, close } = await linkedClient(async (r) => {
      assert.ok(r.url.endsWith("/v1/marketing/capability"));
      return json({ allowed: false, blockers: ["status_not_approved"] });
    });
    t.after(() => close());
    const res: any = await client.callTool({
      name: "marketing_capability",
      arguments: {},
    });
    assert.equal(res.isError, undefined);
    assert.equal(JSON.parse(res.content[0].text).allowed, false);
    assert.equal(calls.length, 1);
  });
});

describe("요청 shaping — 키·도메인", () => {
  it("api_key_list — GET 메타(평문 없음은 API 계약, 결과 그대로)", async () => {
    const { result } = await callOnce("api_key_list", {}, async (r) => {
      assert.equal(r.method, "GET");
      assert.ok(r.url.endsWith("/v1/auth/keys"));
      return json([{ id: "k1", key_prefix: "lb_test_abc" }]);
    });
    assert.equal(result[0].key_prefix, "lb_test_abc");
    assert.ok(!("api_key" in result[0]));
  });

  it("api_key_revoke — DELETE 경로 인코딩", async () => {
    await callOnce(
      "api_key_revoke",
      { key_id: "k/1", confirmed: true },
      async (r) => {
        assert.equal(r.method, "DELETE");
        assert.ok(new URL(r.url).pathname.endsWith("/v1/auth/keys/k%2F1"));
        return json({ revoked: true });
      },
    );
  });

  it("domain_get/dns — GET 경로", async () => {
    await callOnce("domain_get", { domain_id: "dom_1" }, async (r) => {
      assert.ok(r.url.endsWith("/v1/domains/dom_1"));
      return json({ id: "dom_1" });
    });
    await callOnce("domain_dns_records", { domain_id: "dom_1" }, async (r) => {
      assert.ok(r.url.endsWith("/v1/domains/dom_1/dns"));
      return json({ domain: "x.test", records: [] });
    });
  });

  it("domain_verify — POST(읽기 아님, confirmed 필수)", async () => {
    const { result } = await callOnce(
      "domain_verify",
      { domain_id: "dom_1", confirmed: true },
      async (r) => {
        assert.equal(r.method, "POST");
        assert.ok(r.url.endsWith("/v1/domains/dom_1/verify"));
        return json({ id: "dom_1", status: "pending" });
      },
    );
    assert.equal(result.status, "pending");
  });

  it("domain_remove — DELETE", async () => {
    await callOnce(
      "domain_remove",
      { domain_id: "dom_1", confirmed: true },
      async (r) => {
        assert.equal(r.method, "DELETE");
        assert.ok(r.url.endsWith("/v1/domains/dom_1"));
        return json({ id: "dom_1", status: "deleted" });
      },
    );
  });
});

describe("요청 shaping — 마케팅 설정", () => {
  it("audience list/get — GET", async () => {
    await callOnce("marketing_audience_list", {}, async (r) => {
      assert.ok(r.url.endsWith("/v1/marketing/audiences"));
      return json([]);
    });
    await callOnce(
      "marketing_audience_get",
      { audience_public_id: "aud_1" },
      async (r) => {
        assert.ok(r.url.endsWith("/v1/marketing/audiences/aud_1"));
        return json({ public_id: "aud_1" });
      },
    );
  });

  it("audience_create — POST 본문은 백엔드 입력 그대로", async () => {
    await callOnce(
      "marketing_audience_create",
      { name: "News", confirmed: true },
      async (r) => {
        assert.equal(r.method, "POST");
        const b = await r.json();
        assert.deepEqual(Object.keys(b).sort(), ["description", "name"]);
        assert.equal(b.name, "News");
        assert.equal(b.description, null);
        return json({ public_id: "aud_1" }, 201);
      },
    );
  });

  it("sender profile list/get — GET", async () => {
    await callOnce("marketing_sender_profile_list", {}, async (r) => {
      assert.ok(r.url.endsWith("/v1/marketing/sender-profiles"));
      return json([]);
    });
    await callOnce(
      "marketing_sender_profile_get",
      { sender_profile_public_id: "msp_1" },
      async (r) => {
        assert.ok(r.url.endsWith("/v1/marketing/sender-profiles/msp_1"));
        return json({ public_id: "msp_1" });
      },
    );
  });

  it("sender_profile_create — POST 본문은 백엔드 입력 그대로", async () => {
    await callOnce(
      "marketing_sender_profile_create",
      {
        domain_public_id: "dom_1",
        from_name: "News",
        from_address: "news@x.test",
        confirmed: true,
      },
      async (r) => {
        const b = await r.json();
        assert.deepEqual(Object.keys(b).sort(), [
          "domain_public_id",
          "from_address",
          "from_name",
          "reply_to_address",
        ]);
        assert.equal(b.reply_to_address, null);
        return json({ public_id: "msp_1" }, 201);
      },
    );
  });

  it("sender_profile_disable — POST :disable", async () => {
    await callOnce(
      "marketing_sender_profile_disable",
      { sender_profile_public_id: "msp_1", confirmed: true },
      async (r) => {
        assert.equal(r.method, "POST");
        assert.ok(
          r.url.endsWith("/v1/marketing/sender-profiles/msp_1/disable"),
        );
        return json({ public_id: "msp_1", status: "disabled" });
      },
    );
  });
});

describe("구독 동기화 — get/sync", () => {
  it("newsletter_subscription_get — GET + source 쿼리", async () => {
    const { result } = await callOnce(
      "newsletter_subscription_get",
      { audience_public_id: "aud_1", email_hash: HASH, source: "homepage" },
      async (r) => {
        const u = new URL(r.url);
        assert.ok(
          u.pathname.endsWith(
            `/v1/marketing/audiences/aud_1/subscriptions/${HASH}`,
          ),
        );
        assert.equal(u.searchParams.get("source"), "homepage");
        return json({ email_hash: HASH, version: 2, state: "subscribed" });
      },
    );
    assert.equal(result.version, 2);
  });

  it("sync subscribe — PUT 본문 원본 그대로(consent 포함, confirmed 제외)", async () => {
    const { result } = await callOnce(
      "newsletter_subscription_sync",
      {
        audience_public_id: "aud_1",
        email_hash: HASH,
        email: "user@example.com",
        source: "homepage",
        source_revision: 3,
        expected_version: 2,
        action: "subscribe",
        consent: CONSENT,
        confirmed: true,
      },
      async (r) => {
        assert.equal(r.method, "PUT");
        const u = new URL(r.url);
        assert.ok(
          u.pathname.endsWith(
            `/v1/marketing/audiences/aud_1/subscriptions/${HASH}`,
          ),
        );
        const b = await r.json();
        assert.deepEqual(b.consent, CONSENT, "원본 증명 그대로");
        assert.ok(!("confirmed" in b), "confirmed 는 API 로 전송 금지");
        assert.equal(b.source_revision, 3);
        return json({ email_hash: HASH, applied: true, stale: false });
      },
    );
    assert.equal(result.applied, true);
  });

  it("sync unsubscribe — consent 없이 + optout 경고", async () => {
    const { result } = await callOnce(
      "newsletter_subscription_sync",
      {
        audience_public_id: "aud_1",
        email_hash: HASH,
        email: "user@example.com",
        source: "homepage",
        source_revision: 4,
        expected_version: 3,
        action: "unsubscribe",
        confirmed: true,
      },
      async (r) => {
        const b = await r.json();
        assert.ok(!("consent" in b), "unsubscribe 에 consent 없음");
        return json({ email_hash: HASH, applied: true, stale: false });
      },
    );
    assert.equal(result.applied, true);
    assert.match(result.optout_warning, /Org-wide optout/);
  });

  it("sync subscribe consent 누락 — API 호출 없이 isError", async () => {
    const { api, calls } = makeApi(async () => json({}));
    const r = await invokeTool(api, mtool("newsletter_subscription_sync"), {
      audience_public_id: "aud_1",
      email_hash: HASH,
      email: "user@example.com",
      source: "homepage",
      source_revision: 1,
      expected_version: 0,
      action: "subscribe",
      confirmed: true,
    });
    assert.equal(r.isError, true);
    assert.match(r.content[0]!.text, /consent.*필수/);
    assert.equal(calls.length, 0, "검증 실패는 API 호출 없음");
  });

  it("409 충돌 — flat 스냅샷 isError(개정 보존, 무한반사 없음)", async () => {
    const { api } = makeApi(async () =>
      json(
        {
          email_hash: HASH,
          version: 7,
          state: "subscribed",
          block_reason: null,
          last_unsubscribed_at: null,
          source_revision: 5,
          error: "version_conflict",
          api_key: "lb_live_SECRET_MUST_NOT_REFLECT",
          nested: { deep: [1, 2, 3] },
        },
        409,
      ),
    );
    const r = await invokeTool(api, mtool("newsletter_subscription_sync"), {
      audience_public_id: "aud_1",
      email_hash: HASH,
      email: "user@example.com",
      source: "homepage",
      source_revision: 6,
      expected_version: 1,
      action: "subscribe",
      consent: CONSENT,
      confirmed: true,
    });
    assert.equal(r.isError, true);
    const text = r.content[0]!.text;
    assert.match(text, /409/);
    assert.match(text, /version_conflict/);
    const flat = JSON.parse(text.slice(text.indexOf("{")));
    assert.equal(flat.version, 7, "서버 revision 보존");
    assert.equal(flat.source_revision, 5);
    assert.ok(!("api_key" in flat), "시크릿 반사 금지");
    assert.ok(!("nested" in flat), "무한 본문 반사 금지");
    assert.ok(!text.includes("SECRET_MUST_NOT_REFLECT"));
    // structuredContent 로도 정확히 보존.
    const sc = r.structuredContent as Record<string, unknown>;
    assert.ok(sc, "structuredContent 필요");
    assert.equal(sc.status, 409);
    assert.equal(sc.error, "version_conflict");
    assert.equal(sc.version, 7);
    assert.equal(sc.source_revision, 5);
    assert.equal(sc.email_hash, HASH);
  });

  it("422 차단 — flat 스냅샷 isError", async () => {
    const { api } = makeApi(async () =>
      json(
        {
          email_hash: HASH,
          version: 7,
          state: "blocked",
          block_reason: "complaint",
          last_unsubscribed_at: null,
          source_revision: 5,
          error: "recipient_blocked",
        },
        422,
      ),
    );
    const r = await invokeTool(api, mtool("newsletter_subscription_sync"), {
      audience_public_id: "aud_1",
      email_hash: HASH,
      email: "user@example.com",
      source: "homepage",
      source_revision: 6,
      expected_version: 7,
      action: "subscribe",
      consent: CONSENT,
      confirmed: true,
    });
    assert.equal(r.isError, true);
    assert.match(r.content[0]!.text, /recipient_blocked/);
    assert.match(r.content[0]!.text, /complaint/);
  });

  it("pickSyncErrorBody — 허용 키만", () => {
    assert.equal(pickSyncErrorBody(null), null);
    assert.equal(pickSyncErrorBody({}), null);
    const flat = pickSyncErrorBody({
      email_hash: HASH,
      version: 1,
      state: "subscribed",
      block_reason: null,
      last_unsubscribed_at: null,
      source_revision: 2,
      error: "revision_conflict",
      extra: "drop",
    });
    assert.deepEqual(Object.keys(flat!).sort(), [
      "block_reason",
      "email_hash",
      "error",
      "last_unsubscribed_at",
      "source_revision",
      "state",
      "version",
    ]);
  });

  it("pickSyncErrorBody — 무효 스냅샷은 null(해시·정수·타입·상태·시각)", () => {
    const good = {
      email_hash: HASH,
      version: 1,
      state: "subscribed",
      block_reason: null,
      last_unsubscribed_at: null,
      source_revision: 2,
      error: "revision_conflict",
    };
    assert.ok(pickSyncErrorBody(good, 409), "정상 409 스냅샷 통과");
    const cases: Array<[string, Record<string, unknown>]> = [
      ["대문자 해시", { ...good, email_hash: HASH.toUpperCase() }],
      ["짧은 해시", { ...good, email_hash: "abc" }],
      ["음수 version", { ...good, version: -1 }],
      ["소수 version", { ...good, version: 1.5 }],
      ["문자열 version", { ...good, version: "7" }],
      ["상한 초과 version", { ...good, version: MAX_SAFE_INTEGER + 1 }],
      ["음수 source_revision", { ...good, source_revision: -1 }],
      ["불리언 source_revision", { ...good, source_revision: true }],
      ["미지정 state", { ...good, state: "pending" }],
      ["삭제 state", { ...good, state: "deleted" }],
      [
        "미지정 block_reason",
        { ...good, state: "blocked", block_reason: "weird" },
      ],
      [
        "시크릿 block_reason",
        { ...good, state: "blocked", block_reason: "lb_live_SECRET_X" },
      ],
      ["미지정 error", { ...good, error: "unknown_boom" }],
      ["잘못된 시각 문자열", { ...good, last_unsubscribed_at: "어제" }],
      [
        "초과 길이 시각",
        {
          ...good,
          last_unsubscribed_at: `2026-10-01T00:00:00Z${"x".repeat(64)}`,
        },
      ],
      ["숫자 시각", { ...good, last_unsubscribed_at: 1727740800 }],
    ];
    for (const [label, body] of cases) {
      assert.equal(pickSyncErrorBody(body, 409), null, label);
    }
    // error ↔ status 적합성.
    assert.equal(
      pickSyncErrorBody({ ...good, error: "recipient_blocked" }, 409),
      null,
      "409 에 recipient_blocked 불가",
    );
    assert.equal(
      pickSyncErrorBody({ ...good, error: "version_conflict" }, 422),
      null,
      "422 에 version_conflict 불가",
    );
    assert.ok(
      pickSyncErrorBody(
        {
          ...good,
          state: "blocked",
          block_reason: "complaint",
          error: "recipient_blocked",
        },
        422,
      ),
      "정상 422 스냅샷 통과",
    );
    // RFC3339 시각 통과 + 인식된 block_reason 통과.
    assert.ok(
      pickSyncErrorBody({
        ...good,
        last_unsubscribed_at: "2026-10-01T00:00:00Z",
      }),
      "RFC3339 시각 통과",
    );
    for (const br of ["hard_bounce", "complaint", "suppressed", "manual"]) {
      assert.ok(
        pickSyncErrorBody({ ...good, state: "blocked", block_reason: br }),
        `${br} 통과`,
      );
    }
  });

  it("pickSyncErrorBody — oversize 본문은 null", () => {
    const flat = pickSyncErrorBody({
      email_hash: HASH,
      version: 1,
      state: "subscribed",
      block_reason: null,
      last_unsubscribed_at: null,
      source_revision: 2,
      error: "revision_conflict",
      padding: "x".repeat(8192),
    });
    assert.equal(flat, null, "4KiB 초과 본문 거부");
  });

  it("malformed 409/422 — 고정 안전 진단, 원본 시크릿 비반사", async () => {
    const SECRET = "lb_live_MALFORMED_SECRET_9f8e";
    const bodies: Array<[number, unknown]> = [
      [409, { error: { message: `boom ${SECRET}` }, nested: { a: 1 } }],
      [
        409,
        {
          email_hash: HASH,
          version: "7",
          state: "subscribed",
          block_reason: null,
          last_unsubscribed_at: null,
          source_revision: 5,
          error: "version_conflict",
          api_key: SECRET,
        },
      ],
      [
        422,
        {
          email_hash: HASH,
          version: 7,
          state: "blocked",
          block_reason: SECRET,
          last_unsubscribed_at: null,
          source_revision: 5,
          error: "recipient_blocked",
        },
      ],
      [422, "plain text disaster with " + SECRET],
    ];
    for (const [status, body] of bodies) {
      const { api } = makeApi(async () => json(body, status));
      const r = await invokeTool(api, mtool("newsletter_subscription_sync"), {
        audience_public_id: "aud_1",
        email_hash: HASH,
        email: "user@example.com",
        source: "homepage",
        source_revision: 6,
        expected_version: 1,
        action: "subscribe",
        consent: CONSENT,
        confirmed: true,
      });
      assert.equal(r.isError, true, `HTTP ${status} 는 isError`);
      const text = r.content[0]!.text;
      assert.ok(
        text.includes(syncMalformedMessage(status)),
        `고정 진단 필요: ${text}`,
      );
      assert.ok(!text.includes(SECRET), `원본 시크릿 반사 금지: ${text}`);
      assert.equal(r.structuredContent, undefined, "malformed 는 구조화 없음");
    }
  });
});

describe("최소권한 403 안내", () => {
  it("신규 툴 403 은 필요 fine scope 를 지목(막연한 admin 권유 없음)", async () => {
    const { api } = makeApi(async () =>
      json({ error: { message: "forbidden" } }, 403),
    );
    const r = await invokeTool(api, mtool("newsletter_subscription_sync"), {
      audience_public_id: "aud_1",
      email_hash: HASH,
      email: "user@example.com",
      source: "homepage",
      source_revision: 1,
      expected_version: 0,
      action: "unsubscribe",
      confirmed: true,
    });
    assert.equal(r.isError, true);
    assert.match(r.content[0]!.text, /marketing:subscriber:manage/);
    assert.doesNotMatch(r.content[0]!.text, /admin scope/);
  });

  it("describeError — requiredScopes 있을 때만 지목", () => {
    const named = describeError(new ApiError(403, "forbidden"), {
      name: "marketing_capability",
      requiredScopes: ["marketing:read"],
    });
    assert.match(named, /marketing:read/);
    assert.match(named, /권한/);
    const legacy = describeError(new ApiError(403, "forbidden"));
    assert.match(legacy, /권한/);
    assert.doesNotMatch(legacy, /admin scope/);
  });
});

describe("검증 실패는 API 호출 없이 거부", () => {
  it("SDK — confirmed:false 는 호출 전 거부(API 0회)", async (t) => {
    const { client, calls, close } = await linkedClient(async () => json({}));
    t.after(() => close());
    // SDK 는 입력 검증 실패를 reject 가 아닌 isError 결과로 돌린다.
    const res: any = await client.callTool({
      name: "domain_remove",
      arguments: { domain_id: "dom_1", confirmed: false },
    });
    assert.equal(res.isError, true, "confirmed:false 는 isError");
    assert.match(String(res.content[0].text), /confirmed|Invalid/i);
    assert.equal(calls.length, 0);
  });

  it("SDK — domain_verify 확인 누락·오값은 API 호출 없이 거부", async (t) => {
    const { client, calls, close } = await linkedClient(async () => json({}));
    t.after(() => close());
    const missing: any = await client.callTool({
      name: "domain_verify",
      arguments: { domain_id: "dom_1" },
    });
    assert.equal(missing.isError, true, "confirmed 누락은 isError");
    const wrong: any = await client.callTool({
      name: "domain_verify",
      arguments: { domain_id: "dom_1", confirmed: false },
    });
    assert.equal(wrong.isError, true, "confirmed:false 는 isError");
    assert.equal(calls.length, 0, "검증 실패는 API 호출 없음");
  });

  it("SDK — 잘못된 email_hash/source/datetime 은 호출 전 거부", async (t) => {
    const { client, calls, close } = await linkedClient(async () => json({}));
    t.after(() => close());
    const badHash: any = await client.callTool({
      name: "newsletter_subscription_get",
      arguments: {
        audience_public_id: "aud_1",
        email_hash: "ZZZ",
        source: "homepage",
      },
    });
    assert.equal(badHash.isError, true, "잘못된 email_hash 는 isError");
    const badSource: any = await client.callTool({
      name: "newsletter_subscription_get",
      arguments: {
        audience_public_id: "aud_1",
        email_hash: HASH,
        source: "Home Page!",
      },
    });
    assert.equal(badSource.isError, true, "잘못된 source 는 isError");
    const badTime: any = await client.callTool({
      name: "newsletter_subscription_sync",
      arguments: {
        audience_public_id: "aud_1",
        email_hash: HASH,
        email: "user@example.com",
        source: "homepage",
        source_revision: 1,
        expected_version: 0,
        action: "subscribe",
        consent: { ...CONSENT, collected_at: "어제" },
        confirmed: true,
      },
    });
    assert.equal(badTime.isError, true, "잘못된 datetime 은 isError");
    assert.equal(calls.length, 0);
  });

  it("zod — 정수 상한(MAX_SAFE_INTEGER)", () => {
    const shape = mtool("newsletter_subscription_sync").inputSchema as Record<
      string,
      z.ZodTypeAny
    >;
    const rev = shape.source_revision as z.ZodNumber;
    assert.ok(!rev.safeParse(0).success, "revision 0 불가");
    assert.ok(!rev.safeParse(MAX_SAFE_INTEGER + 1).success, "상한 초과 불가");
    assert.ok(rev.safeParse(MAX_SAFE_INTEGER).success);
    const ver = shape.expected_version as z.ZodNumber;
    assert.ok(ver.safeParse(0).success, "version 0 허용");
    assert.ok(!ver.safeParse(-1).success);
  });
});

describe("read-only 모드", () => {
  it("isReadOnlyFromEnv — 명시 true 일 때만", () => {
    assert.equal(isReadOnlyFromEnv({}), false);
    assert.equal(
      isReadOnlyFromEnv({ LOFTBOX_MCP_READ_ONLY: undefined }),
      false,
    );
    assert.equal(isReadOnlyFromEnv({ LOFTBOX_MCP_READ_ONLY: "true" }), true);
    assert.equal(isReadOnlyFromEnv({ LOFTBOX_MCP_READ_ONLY: "TRUE" }), true);
    assert.equal(isReadOnlyFromEnv({ LOFTBOX_MCP_READ_ONLY: "1" }), false);
    assert.equal(isReadOnlyFromEnv({ LOFTBOX_MCP_READ_ONLY: "yes" }), false);
    assert.equal(isReadOnlyFromEnv({ LOFTBOX_MCP_READ_ONLY: "" }), false);
  });

  it("readOnly 서버 — 쓰기 미등록(수동 지명 호출 불가), 읽기만", async (t) => {
    const { client, calls, close } = await linkedClient(
      async () => json({ allowed: true, blockers: [] }),
      true,
    );
    t.after(() => close());
    const { tools } = await client.listTools();
    const names = tools.map((tool) => tool.name);
    assert.ok(names.includes("marketing_capability"), "읽기 노출");
    assert.ok(names.includes("auth_context"), "읽기 노출");
    for (const w of [
      "api_key_revoke",
      "domain_verify",
      "domain_remove",
      "marketing_audience_create",
      "marketing_sender_profile_create",
      "marketing_sender_profile_disable",
      "newsletter_subscription_sync",
      "message_send",
    ]) {
      assert.ok(!names.includes(w), `${w} 숨김 필요`);
    }
    // 읽기 호출은 정상.
    const res: any = await client.callTool({
      name: "marketing_capability",
      arguments: {},
    });
    assert.equal(res.isError, undefined);
    assert.equal(calls.length, 1);
    // 숨김 쓰기를 수동 지명해도 isError 로 거부(API 호출 없음, reject 아님).
    const hidden: any = await client.callTool({
      name: "newsletter_subscription_sync",
      arguments: {
        audience_public_id: "aud_1",
        email_hash: HASH,
        email: "user@example.com",
        source: "homepage",
        source_revision: 1,
        expected_version: 0,
        action: "unsubscribe",
        confirmed: true,
      },
    });
    assert.equal(hidden.isError, true, "숨김 쓰기는 isError");
    assert.match(String(hidden.content[0].text), /not found|disabled/i);
    assert.equal(calls.length, 1, "숨김 쓰기는 API 호출 없음");
  });

  it("기본 서버 — 쓰기 등록 유지", async (t) => {
    const { client, close } = await linkedClient(async () => json({}), false);
    t.after(() => close());
    const { tools } = await client.listTools();
    assert.ok(
      tools.find((tool) => tool.name === "newsletter_subscription_sync"),
    );
  });
});

describe("stdio 진입 env 배선", () => {
  const PKG_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
  const ENTRY = join(PKG_ROOT, "src", "index.ts");

  it("키 없으면 exit 1 + stderr 안내", { timeout: 30000 }, async () => {
    const env = { ...process.env };
    delete env.LOFTBOX_API_KEY;
    const child = spawn(process.execPath, ["--import", "tsx", ENTRY], {
      env,
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr += String(d);
    });
    const code: number = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error("stdio 진입 타임아웃"));
      }, 25000);
      child.on("error", reject);
      child.on("close", (c) => {
        clearTimeout(timer);
        resolve(c ?? 1);
      });
    });
    assert.equal(code, 1, "키 없으면 exit 1");
    assert.match(stderr, /LOFTBOX_API_KEY/);
  });

  it(
    "LOFTBOX_MCP_READ_ONLY=true — stdio 실프로세스에서 관리 쓰기 미노출",
    { timeout: 60000 },
    async () => {
      const transport = new StdioClientTransport({
        command: process.execPath,
        args: ["--import", "tsx", ENTRY],
        env: {
          ...process.env,
          LOFTBOX_API_KEY: "lb_test_stdio",
          LOFTBOX_MCP_READ_ONLY: "true",
        } as Record<string, string>,
      });
      const client = new Client({ name: "test", version: "0" });
      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        const names = tools.map((tool) => tool.name);
        assert.ok(names.includes("auth_context"), "읽기 노출");
        for (const w of [
          "api_key_revoke",
          "domain_verify",
          "domain_remove",
          "newsletter_subscription_sync",
        ]) {
          assert.ok(!names.includes(w), `stdio read-only 에서 ${w} 숨김 필요`);
        }
      } finally {
        await client.close();
      }
    },
  );
});
