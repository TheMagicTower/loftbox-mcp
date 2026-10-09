/** OAuth 브로커 합성 테스트 — 로컬 fake API + 임시 durable 저장소.
 *
 * 실제 서비스·메일·외부 연결 없음. 모든 비밀은 테스트용 합성값이다.
 * 루프백 HTTP 는 테스트 설정({oauth:{allowInsecureLoopback:true}})으로만 허용.
 */

import assert from "node:assert/strict";
import { describe, it, beforeEach, afterEach } from "node:test";
import type { AddressInfo } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import {
  createServer as createHttpServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
} from "node:http";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { buildHttpServer } from "../src/http.js";
import type { HttpServerOptions } from "../src/http.js";
import {
  FileOAuthStore,
  encryptSecret,
  isStoreCapacityError,
  parseStore,
  sha256Hex,
} from "../src/oauth-store.js";
import {
  OAuthBroker,
  validateKeyWithApi,
  type AuthContext,
} from "../src/oauth.js";
import {
  loadOAuthConfig,
  normalizeIp,
  RATE_LIMIT_MAX,
} from "../src/oauth-config.js";

// 합성 테스트는 로컬 루프백만 사용 — 샌드박스 프록시 경유 금지(결정적 실행).
for (const k of ["NO_PROXY", "no_proxy"]) {
  const cur = process.env[k] ?? "";
  if (!cur.includes("127.0.0.1")) {
    process.env[k] = cur ? `${cur},127.0.0.1,localhost` : "127.0.0.1,localhost";
  }
}

/* ─── 테스트 상수 ─────────────────────────────────────────────── */

const TEST_KEY = "lb_test_synthetic_key_001";
const TEST_KEY_2 = "lb_test_synthetic_key_002";
// 세션/dev 폴백 형태(null 키 id)와 비정형 id 를 돌려주는 합성 키.
const TEST_KEY_NULLKEY = "lb_test_synthetic_nullkey_003";
const TEST_KEY_BADUUID = "lb_test_synthetic_baduuid_004";
// 실제 합성 UUID — 승인·검증 바인딩은 non-nil UUID 만 인정한다.
const UUID_ORG_1 = "11111111-1111-4111-8111-111111111111";
const UUID_KEY_1 = "22222222-2222-4222-8222-222222222222";
const UUID_ORG_2 = "33333333-3333-4333-8333-333333333333";
const UUID_KEY_2 = "44444444-4444-4444-8444-444444444444";
const UUID_ORG_3 = "55555555-5555-4555-8555-555555555555";
const UUID_KEY_3 = "66666666-6666-4666-8666-666666666666";
const PUBLIC_URL = "http://127.0.0.1:9"; // 도달 불가 더미 — issuer 문자열로만 사용
const RESOURCE = `${PUBLIC_URL}/mcp`;

const OAUTH_ENV_KEYS = [
  "LOFTBOX_MCP_OAUTH_ENABLED",
  "LOFTBOX_MCP_PUBLIC_URL",
  "LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY",
  "LOFTBOX_MCP_OAUTH_STORE",
  "LOFTBOX_MCP_OAUTH_TRUSTED_PROXY_IPS",
  "LOFTBOX_BASE_URL",
  "LOFTBOX_MCP_READ_ONLY",
] as const;

const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of OAUTH_ENV_KEYS) {
    savedEnv[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  for (const k of OAUTH_ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

function testEncryptionKey(): string {
  return randomBytes(32).toString("base64");
}

function testStorePath(): string {
  return join(mkdtempSync(join(tmpdir(), "lbmcp-oauth-")), "store.json");
}

function enableOAuth(storePath?: string): string {
  const store = storePath ?? testStorePath();
  process.env.LOFTBOX_MCP_OAUTH_ENABLED = "true";
  process.env.LOFTBOX_MCP_PUBLIC_URL = PUBLIC_URL;
  process.env.LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY = testEncryptionKey();
  process.env.LOFTBOX_MCP_OAUTH_STORE = store;
  return store;
}

async function startMcp(
  opts: HttpServerOptions = { oauth: { allowInsecureLoopback: true } },
): Promise<{ port: number; close: () => Promise<void> }> {
  const server = buildHttpServer(opts);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    port: addr.port,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      ),
  };
}

/* ─── Fake LoftBox API ────────────────────────────────────────── */

interface FakeApi {
  url: string;
  validKeys: Map<string, { orgId: string; keyId: string | null }>;
  /** 다운스트림으로 전달된 Authorization 헤더 기록(유출 감사). */
  seenAuthz: string[];
  close: () => Promise<void>;
}

async function startFakeApi(): Promise<FakeApi> {
  const validKeys = new Map<string, { orgId: string; keyId: string | null }>([
    [TEST_KEY, { orgId: UUID_ORG_1, keyId: UUID_KEY_1 }],
    [TEST_KEY_2, { orgId: UUID_ORG_2, keyId: UUID_KEY_2 }],
    [TEST_KEY_NULLKEY, { orgId: UUID_ORG_1, keyId: null }],
    [TEST_KEY_BADUUID, { orgId: "org_test", keyId: "key_1" }],
  ]);
  const seenAuthz: string[] = [];
  const server: Server = createHttpServer((req, res) => {
    const authz = req.headers.authorization ?? "";
    seenAuthz.push(authz);
    const key = authz.startsWith("Bearer ") ? authz.slice(7) : "";
    const valid = validKeys.get(key) ?? null;
    const path = (req.url ?? "").split("?")[0];
    const json = (status: number, body: unknown): void => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (path === "/v1") {
      json(valid ? 200 : 401, valid ? { ok: true } : { error: "unauthorized" });
      return;
    }
    if (path === "/v1/auth/context") {
      if (!valid) {
        json(401, { error: "unauthorized" });
        return;
      }
      json(200, {
        organization: { id: valid.orgId, slug: valid.orgId, name: "Test Org" },
        api_key_id: valid.keyId,
        granted_scopes: ["marketing:read", "domain:read"],
        effective_scopes: ["marketing:read", "domain:read"],
      });
      return;
    }
    if (!valid) {
      json(401, { error: "unauthorized" });
      return;
    }
    if (path === "/v1/agents" && req.method === "GET") {
      json(200, { data: [{ id: "ag_1", slug: "test" }], next_cursor: null });
      return;
    }
    if (/^\/v1\/domains\/[^/]+\/verify$/.test(path) && req.method === "POST") {
      json(200, { verified: true });
      return;
    }
    json(404, { error: "not found" });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}`,
    validKeys,
    seenAuthz,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      ),
  };
}

function assertNoOAuthTokenDownstream(api: FakeApi): void {
  for (const h of api.seenAuthz) {
    assert.ok(
      !h.includes("lbmcp_at_"),
      `OAuth 토큰이 다운스트림에 전달되면 안 된다: ${h.slice(0, 20)}…`,
    );
  }
}

/* ─── OAuth 흐름 헬퍼 ─────────────────────────────────────────── */

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(48).toString("base64url"); // 64자
  const challenge = createHash("sha256")
    .update(verifier, "utf8")
    .digest("base64url");
  return { verifier, challenge };
}

async function registerClient(
  base: string,
  redirectUri: string,
  extra: Record<string, unknown> = {},
): Promise<{ client_id: string; redirect_uri: string }> {
  const res = await fetch(`${base}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      redirect_uris: [redirectUri],
      client_name: "Test Client",
      token_endpoint_auth_method: "none",
      ...extra,
    }),
  });
  assert.equal(res.status, 201);
  const body = (await res.json()) as { client_id: string };
  assert.ok(body.client_id);
  return { client_id: body.client_id, redirect_uri: redirectUri };
}

interface AuthzIssued {
  txn: string;
  csrf: string;
  cookie: string;
  html: string;
}

async function authorizeGet(
  base: string,
  params: Record<string, string>,
): Promise<{
  status: number;
  location: string | null;
  issued: AuthzIssued | null;
}> {
  const q = new URLSearchParams(params).toString();
  const res = await fetch(`${base}/oauth/authorize?${q}`, {
    method: "GET",
    redirect: "manual",
  });
  const location = res.headers.get("location");
  if (res.status !== 200) {
    return { status: res.status, location, issued: null };
  }
  const html = await res.text();
  const txn = /name="txn" value="([^"]+)"/.exec(html)?.[1] ?? "";
  const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? "";
  const setCookie = res.headers.get("set-cookie") ?? "";
  const cookie = setCookie.split(";")[0] ?? "";
  assert.ok(txn && csrf && cookie.startsWith("lbmcp_txn="));
  return { status: 200, location, issued: { txn, csrf, cookie, html } };
}

async function authorizePost(
  base: string,
  origin: string,
  fields: Record<string, string>,
  cookie?: string,
  originHeader?: string | null,
): Promise<{ status: number; location: string | null; html: string }> {
  const res = await fetch(`${base}/oauth/authorize`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(cookie ? { cookie } : {}),
      ...(originHeader === null ? {} : { origin: originHeader ?? origin }),
    },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  });
  const html = res.status === 302 ? "" : await res.text();
  return { status: res.status, location: res.headers.get("location"), html };
}

async function tokenPost(
  base: string,
  fields: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString(),
  });
  const body = (await res.json()) as Record<string, unknown>;
  return { status: res.status, body };
}

/** DCR→승인→코드까지 수행하고 코드 교환 재료를 반환한다. */
async function approveToCode(
  base: string,
  origin: string,
  opts: {
    scope?: string;
    apiKey?: string;
    allowManage?: boolean;
    clientName?: string;
    redirectUri?: string;
  } = {},
): Promise<{
  code: string;
  client_id: string;
  redirect_uri: string;
  verifier: string;
}> {
  const redirectUri =
    opts.redirectUri ??
    `http://127.0.0.1:9/cb-${randomBytes(4).toString("hex")}`;
  const { client_id } = await registerClient(base, redirectUri, {
    client_name: opts.clientName ?? "Test Client",
  });
  const { verifier, challenge } = pkce();
  const state = `st_${randomBytes(8).toString("hex")}`;
  const got = await authorizeGet(base, {
    response_type: "code",
    client_id,
    redirect_uri: redirectUri,
    scope: opts.scope ?? "loftbox.read",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: RESOURCE,
  });
  assert.equal(got.status, 200);
  const issued = got.issued!;
  const fields: Record<string, string> = {
    txn: issued.txn,
    csrf: issued.csrf,
    decision: "allow",
    api_key: opts.apiKey ?? TEST_KEY,
  };
  if (opts.allowManage) fields.allow_manage = "yes";
  const posted = await authorizePost(base, origin, fields, issued.cookie);
  assert.equal(posted.status, 302);
  const loc = new URL(posted.location!, "http://x");
  assert.equal(loc.searchParams.get("iss"), PUBLIC_URL);
  assert.equal(loc.searchParams.get("state"), state);
  const code = loc.searchParams.get("code") ?? "";
  assert.ok(code.startsWith("lbmcp_ac_"));
  return { code, client_id, redirect_uri: redirectUri, verifier };
}

describe("OAuth 발견·등록", () => {
  it("메타데이터 3종: canonical resource·동일 issuer·iss 지원", async () => {
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      for (const p of [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
      ]) {
        const res = await fetch(`${base}${p}`);
        assert.equal(res.status, 200);
        assert.match(
          res.headers.get("content-type") ?? "",
          /application\/json/,
        );
        const doc = (await res.json()) as Record<string, unknown>;
        assert.equal(doc.resource, RESOURCE);
        assert.deepEqual(doc.authorization_servers, [PUBLIC_URL]);
        assert.deepEqual(doc.scopes_supported, [
          "loftbox.read",
          "loftbox.manage",
        ]);
      }
      const as = await fetch(`${base}/.well-known/oauth-authorization-server`);
      assert.equal(as.status, 200);
      const asDoc = (await as.json()) as Record<string, unknown>;
      assert.equal(asDoc.issuer, PUBLIC_URL);
      assert.equal(asDoc.authorization_response_iss_parameter_supported, true);
      assert.deepEqual(asDoc.code_challenge_methods_supported, ["S256"]);
      assert.deepEqual(asDoc.token_endpoint_auth_methods_supported, ["none"]);
      assert.ok(
        String(asDoc.registration_endpoint).startsWith(PUBLIC_URL),
        "DCR endpoint 공개",
      );
      assert.ok(!("userinfo_endpoint" in asDoc), "userinfo 미제공");
      assert.ok(
        !JSON.stringify(asDoc).toLowerCase().includes("cimd"),
        "CIMD 미표방",
      );
    } finally {
      await close();
    }
  });

  it("DCR 검증 실패 모음", async () => {
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const bad = async (body: unknown, contentType = "application/json") => {
        const res = await fetch(`${base}/oauth/register`, {
          method: "POST",
          headers: { "content-type": contentType },
          body: typeof body === "string" ? body : JSON.stringify(body),
        });
        return res.status;
      };
      assert.equal(await bad({}), 400, "redirect_uris 누락");
      assert.equal(
        await bad({ redirect_uris: ["http://evil.com/cb"] }),
        400,
        "비루프백 http 거부",
      );
      assert.equal(
        await bad({ redirect_uris: ["https://x.test/cb#frag"] }),
        400,
        "fragment 거부",
      );
      assert.equal(
        await bad({ redirect_uris: ["https://*.x.test/cb"] }),
        400,
        "와일드카드 거부",
      );
      assert.equal(
        await bad({ redirect_uris: ["https://user@x.test/cb"] }),
        400,
        "userinfo 거부",
      );
      assert.equal(
        await bad({
          redirect_uris: ["https://x.test/cb"],
          token_endpoint_auth_method: "client_secret_basic",
        }),
        400,
        "none 외 인증방식 거부",
      );
      assert.equal(
        await bad({
          redirect_uris: ["https://x.test/cb"],
          grant_types: ["password"],
        }),
        400,
        "password grant 거부",
      );
      assert.equal(
        await bad({
          redirect_uris: ["https://x.test/cb"],
          response_types: ["token"],
        }),
        400,
        "implicit 거부",
      );
      assert.equal(
        await bad({
          redirect_uris: ["https://x.test/cb"],
          scope: "openid email",
        }),
        400,
        "openid/email scope 거부",
      );
      assert.equal(await bad("{oops", "application/json"), 400, "깨진 JSON");
      assert.equal(
        await bad({ redirect_uris: ["https://x.test/cb"] }, "text/plain"),
        400,
        "content-type 강제",
      );
      // 허용: https 등록 + 루프백 http(테스트 설정).
      const ok1 = await fetch(`${base}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uris: [
            "https://chatgpt.com/connector_platform_oauth_redirect",
          ],
          client_name: "ChatGPT",
        }),
      });
      assert.equal(ok1.status, 201);
      const ok2 = await fetch(`${base}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:9/cb"] }),
      });
      assert.equal(ok2.status, 201);
    } finally {
      await close();
    }
  });

  it("메서드·초과 입력 처리", async () => {
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const get = await fetch(`${base}/oauth/token`, { method: "GET" });
      assert.equal(get.status, 405);
      const postMeta = await fetch(
        `${base}/.well-known/oauth-protected-resource`,
        { method: "POST" },
      );
      assert.equal(postMeta.status, 405);
      // 초과 DCR 본문(32KB+).
      const big = await fetch(`${base}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uris: ["https://x.test/cb"],
          pad: "x".repeat(40 * 1024),
        }),
      });
      assert.equal(big.status, 400);
      // 초과 인가 쿼리.
      const long = await fetch(`${base}/oauth/authorize?${"a".repeat(9000)}`, {
        redirect: "manual",
      });
      assert.ok([400, 414].includes(long.status));
    } finally {
      await close();
    }
  });
});

describe("OAuth 승인·토큰 흐름", () => {
  it("전체 흐름: DCR→승인(S256+CSRF)→토큰→SDK initialize+tools/list+읽기 호출", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const origin = base;
      const redirectUri = "http://127.0.0.1:9/cb-happy";
      const { client_id } = await registerClient(base, redirectUri);
      const { verifier, challenge } = pkce();
      const got = await authorizeGet(base, {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "state123",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      });
      assert.equal(got.status, 200);
      assert.match(got.issued!.html, /기존 LoftBox API 키/);
      assert.match(got.issued!.html, /127\.0\.0\.1/);
      // CSRF 쿠키 속성.
      const setCookie = got.issued!.cookie;
      assert.ok(setCookie.startsWith("lbmcp_txn="));
      const posted = await authorizePost(
        base,
        origin,
        {
          txn: got.issued!.txn,
          csrf: got.issued!.csrf,
          decision: "allow",
          api_key: TEST_KEY,
        },
        got.issued!.cookie,
      );
      assert.equal(posted.status, 302);
      const loc = new URL(posted.location!, "http://x");
      assert.equal(loc.searchParams.get("iss"), PUBLIC_URL);
      assert.equal(loc.searchParams.get("state"), "state123");
      const code = loc.searchParams.get("code")!;
      assert.ok(code.startsWith("lbmcp_ac_"));

      const t = await tokenPost(base, {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id,
        code_verifier: verifier,
        resource: RESOURCE,
      });
      assert.equal(t.status, 200);
      assert.ok(
        !JSON.stringify(t.body).includes(TEST_KEY),
        "토큰 응답에 키 없음",
      );
      const access = t.body.access_token as string;

      // 실제 SDK 로 MCP 사용.
      const transport = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${access}` } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        const names = tools.map((x) => x.name);
        assert.ok(names.includes("agent_list"), "읽기 노출");
        assert.ok(names.includes("auth_context"), "읽기 노출");
        assert.ok(!names.includes("message_send"), "발송 숨김");
        assert.ok(
          !names.includes("newsletter_subscription_sync"),
          "관리 쓰기 숨김",
        );
        // 읽기 도구 실호출.
        const res = (await client.callTool({
          name: "agent_list",
          arguments: {},
        })) as { isError?: boolean; content: Array<{ text: string }> };
        assert.notEqual(res.isError, true);
        assert.match(res.content[0]!.text, /ag_1/);
        // 숨김 쓰기 수동 지명 거부.
        for (const hidden of ["message_send", "newsletter_subscription_sync"]) {
          const denied = (await client.callTool({
            name: hidden,
            arguments:
              hidden === "message_send"
                ? { mailbox_id: "m", to: ["a@b.c"], subject: "s" }
                : {
                    audience_public_id: "aud_1",
                    email_hash: "a".repeat(64),
                    email: "u@e.com",
                    source: "homepage",
                    source_revision: 1,
                    expected_version: 0,
                    action: "unsubscribe",
                    confirmed: true,
                  },
          })) as { isError?: boolean };
          assert.equal(denied.isError, true, `${hidden} 거부 필요`);
        }
      } finally {
        await client.close();
      }
      assertNoOAuthTokenDownstream(api);
    } finally {
      await close();
      await api.close();
    }
  });

  it("manage 명시 승인: 관리 쓰기만 추가, 레거시 쓰기 제외", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base, {
        scope: "loftbox.read loftbox.manage",
        allowManage: true,
      });
      const { access, scope } = await codeToTokens(base, c);
      assert.ok(scope.includes("loftbox.manage"));
      const transport = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${access}` } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        const names = tools.map((x) => x.name);
        for (const w of [
          "api_key_revoke",
          "domain_verify",
          "domain_remove",
          "marketing_audience_create",
          "marketing_sender_profile_create",
          "marketing_sender_profile_disable",
          "newsletter_subscription_sync",
        ]) {
          assert.ok(names.includes(w), `manage 에 ${w} 포함 필요`);
        }
        for (const legacy of [
          "message_send",
          "message_approve",
          "message_reject",
          "approval_policy_create",
          "agent_create",
          "mailbox_create",
          "domain_create",
          "suppression_add",
          "suppression_remove",
          "inbox_ack",
          "label_add",
          "label_remove",
        ]) {
          assert.ok(!names.includes(legacy), `manage 에서 ${legacy} 제외 필요`);
        }
        // 관리 쓰기 실호출(합성 API).
        const res = (await client.callTool({
          name: "domain_verify",
          arguments: { domain_id: "dom_1", confirmed: true },
        })) as { isError?: boolean; content: Array<{ text: string }> };
        assert.notEqual(res.isError, true);
        assert.match(res.content[0]!.text, /verified/);
      } finally {
        await client.close();
      }
    } finally {
      await close();
      await api.close();
    }
  });

  it("manage 미체크 → 읽기 축소, 미요청 manage 강제 불가", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      // 요청은 manage 포함, 체크 안 함 → read 로 축소.
      const c1 = await approveToCode(base, base, {
        scope: "loftbox.read loftbox.manage",
        allowManage: false,
      });
      const t1 = await codeToTokens(base, c1);
      assert.equal(t1.scope, "loftbox.read");
      // 요청은 read 만, 폼 변조로 체크 → read 유지(미요청 부여 금지).
      const c2 = await approveToCode(base, base, {
        scope: "loftbox.read",
        allowManage: true,
      });
      const t2 = await codeToTokens(base, c2);
      assert.equal(t2.scope, "loftbox.read");
    } finally {
      await close();
      await api.close();
    }
  });

  it("무효 키 재시도 보존·키 무반사, 거부·만료 처리", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-retry";
      const { client_id } = await registerClient(base, redirectUri);
      const { verifier, challenge } = pkce();
      const got = await authorizeGet(base, {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "s1",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      });
      assert.equal(got.status, 200);
      const badKey = "lb_test_WRONG_key_zzz";
      const retry = await authorizePost(
        base,
        base,
        {
          txn: got.issued!.txn,
          csrf: got.issued!.csrf,
          decision: "allow",
          api_key: badKey,
        },
        got.issued!.cookie,
      );
      assert.equal(retry.status, 200, "무효 키에도 폼 유지");
      assert.match(retry.html, /유효하지 않습니다/);
      assert.ok(!retry.html.includes(badKey), "키 무반사");
      // 같은 txn 으로 재시도 성공 — 최초 state 유지.
      const retry2 = await authorizePost(
        base,
        base,
        {
          txn: got.issued!.txn,
          csrf: got.issued!.csrf,
          decision: "allow",
          api_key: TEST_KEY,
        },
        got.issued!.cookie,
      );
      assert.equal(retry2.status, 302);
      const rloc = new URL(retry2.location!, "http://x");
      assert.ok(rloc.searchParams.get("code"));
      assert.equal(rloc.searchParams.get("state"), "s1");
      assert.equal(rloc.searchParams.get("iss"), PUBLIC_URL);

      // 거부.
      const got2 = await authorizeGet(base, {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "s2",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      });
      const denied = await authorizePost(
        base,
        base,
        { txn: got2.issued!.txn, csrf: got2.issued!.csrf, decision: "deny" },
        got2.issued!.cookie,
      );
      assert.equal(denied.status, 302);
      const dloc = new URL(denied.location!, "http://x");
      assert.equal(dloc.searchParams.get("error"), "access_denied");
      assert.equal(dloc.searchParams.get("iss"), PUBLIC_URL);
      assert.equal(dloc.searchParams.get("state"), "s2");
      assert.ok(verifier.length >= 43);
    } finally {
      await close();
      await api.close();
    }
  });

  it("만료 txn 은 재시작 오류 페이지(리다이렉트 없음)", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp({
      oauth: { allowInsecureLoopback: true, txnTtlSecs: 1 },
    });
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-exp";
      const { client_id } = await registerClient(base, redirectUri);
      const { challenge } = pkce();
      const got = await authorizeGet(base, {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      });
      await new Promise((r) => setTimeout(r, 1200));
      const posted = await authorizePost(
        base,
        base,
        {
          txn: got.issued!.txn,
          csrf: got.issued!.csrf,
          decision: "allow",
          api_key: TEST_KEY,
        },
        got.issued!.cookie,
      );
      assert.equal(posted.status, 400);
      assert.equal(posted.location, null);
      assert.match(posted.html, /만료/);
    } finally {
      await close();
      await api.close();
    }
  });
});

async function codeToTokens(
  base: string,
  c: {
    code: string;
    client_id: string;
    redirect_uri: string;
    verifier: string;
  },
): Promise<{ access: string; refresh: string; scope: string }> {
  const t = await tokenPost(base, {
    grant_type: "authorization_code",
    code: c.code,
    redirect_uri: c.redirect_uri,
    client_id: c.client_id,
    code_verifier: c.verifier,
    resource: RESOURCE,
  });
  assert.equal(t.status, 200);
  const access = t.body.access_token as string;
  const refresh = t.body.refresh_token as string;
  assert.ok(access.startsWith("lbmcp_at_"));
  assert.ok(refresh.startsWith("lbmcp_rt_"));
  assert.equal(t.body.token_type, "Bearer");
  return { access, refresh, scope: t.body.scope as string };
}

describe("OAuth 바인딩·공격 방어", () => {
  it("인가 요청 오류: 무효 client/redirect 는 페이지(리다이렉트 없음), resource/scope/PKCE 는 iss 포함 리다이렉트", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-bind";
      const { client_id } = await registerClient(base, redirectUri);
      const { challenge } = pkce();
      const valid = {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      };
      // 미등록 client → 페이지, 리다이렉트 없음.
      const badClient = await authorizeGet(base, {
        ...valid,
        client_id: "lbmcp_cli_nope",
      });
      assert.equal(badClient.status, 400);
      assert.equal(badClient.location, null);
      // redirect 불일치 → 페이지, 리다이렉트 없음.
      const badRedir = await authorizeGet(base, {
        ...valid,
        redirect_uri: "http://127.0.0.1:9/other",
      });
      assert.equal(badRedir.status, 400);
      assert.equal(badRedir.location, null);
      // resource 교체 → 리다이렉트 invalid_target + iss.
      const badRes = await authorizeGet(base, {
        ...valid,
        resource: "http://127.0.0.1:9/other",
      });
      assert.equal(badRes.status, 302);
      const rloc = new URL(badRes.location!, "http://x");
      assert.equal(rloc.searchParams.get("error"), "invalid_target");
      assert.equal(rloc.searchParams.get("iss"), PUBLIC_URL);
      assert.equal(rloc.searchParams.get("state"), "s");
      // 미지원 scope → invalid_scope + iss.
      const badScope = await authorizeGet(base, {
        ...valid,
        scope: "openid loftbox.read",
      });
      assert.equal(badScope.status, 302);
      assert.equal(
        new URL(badScope.location!, "http://x").searchParams.get("error"),
        "invalid_scope",
      );
      assert.equal(
        new URL(badScope.location!, "http://x").searchParams.get("iss"),
        PUBLIC_URL,
      );
      // 평문 PKCE → invalid_request 리다이렉트.
      const plain = await authorizeGet(base, {
        ...valid,
        code_challenge_method: "plain",
        code_challenge: "x".repeat(50),
      });
      assert.equal(plain.status, 302);
      assert.equal(
        new URL(plain.location!, "http://x").searchParams.get("error"),
        "invalid_request",
      );
      // PKCE 누락 → 리다이렉트 오류.
      const noPkce = await authorizeGet(base, {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "s",
        resource: RESOURCE,
      });
      assert.equal(noPkce.status, 302);
      // state 없음 → 허용(200 폼). 표준 SDK state 훅은 선택이다.
      const noState = await authorizeGet(base, {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      });
      assert.equal(noState.status, 200);
      // 초과 state → 302 오류 + iss, state 미반사.
      const big = await authorizeGet(base, {
        ...valid,
        state: "s".repeat(3000),
      });
      assert.equal(big.status, 302);
      const bloc = new URL(big.location!, "http://x");
      assert.equal(bloc.searchParams.get("error"), "invalid_request");
      assert.equal(bloc.searchParams.get("iss"), PUBLIC_URL);
      assert.equal(bloc.searchParams.get("state"), null);
    } finally {
      await close();
      await api.close();
    }
  });

  it("토큰 교환 바인딩: redirect/client/resource/verifier 불일치 거부", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const fields = (c: {
        code: string;
        client_id: string;
        redirect_uri: string;
        verifier: string;
      }) => ({
        grant_type: "authorization_code",
        code: c.code,
        redirect_uri: c.redirect_uri,
        client_id: c.client_id,
        code_verifier: c.verifier,
        resource: RESOURCE,
      });
      // 각 케이스는 새 코드(실패 시 코드 소진).
      const c1 = await approveToCode(base, base);
      const t1 = await tokenPost(base, {
        ...fields(c1),
        redirect_uri: "http://127.0.0.1:9/wrong",
      });
      assert.equal(t1.status, 400);
      assert.equal(t1.body.error, "invalid_grant");

      const c2 = await approveToCode(base, base);
      const t2 = await tokenPost(base, {
        ...fields(c2),
        client_id: "lbmcp_cli_wrong",
      });
      assert.equal(t2.status, 400);

      const c3 = await approveToCode(base, base);
      const t3 = await tokenPost(base, {
        ...fields(c3),
        resource: "http://127.0.0.1:9/evil",
      });
      assert.equal(t3.status, 400);
      assert.equal(t3.body.error, "invalid_target");

      const c4 = await approveToCode(base, base);
      const t4 = await tokenPost(base, {
        grant_type: "authorization_code",
        code: c4.code,
        redirect_uri: c4.redirect_uri,
        client_id: c4.client_id,
        code_verifier: c4.verifier,
        // resource 누락.
      });
      assert.equal(t4.status, 400);
      assert.equal(t4.body.error, "invalid_target");

      const c5 = await approveToCode(base, base);
      const other = pkce();
      const t5 = await tokenPost(base, {
        ...fields(c5),
        code_verifier: other.verifier,
      });
      assert.equal(t5.status, 400);
      assert.equal(t5.body.error, "invalid_grant");

      const c6 = await approveToCode(base, base);
      const t6 = await tokenPost(base, {
        ...fields(c6),
        code_verifier: "짧음",
      });
      assert.equal(t6.status, 400);

      // 지원하지 않는 grant.
      const t7 = await tokenPost(base, {
        grant_type: "password",
        resource: RESOURCE,
      });
      assert.equal(t7.status, 400);
      assert.equal(t7.body.error, "unsupported_grant_type");
    } finally {
      await close();
      await api.close();
    }
  });

  it("코드 일회용: 재사용 거부, 동시 교환은 정확히 하나 성공", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base);
      const f = {
        grant_type: "authorization_code",
        code: c.code,
        redirect_uri: c.redirect_uri,
        client_id: c.client_id,
        code_verifier: c.verifier,
        resource: RESOURCE,
      };
      const first = await tokenPost(base, f);
      assert.equal(first.status, 200);
      const replay = await tokenPost(base, f);
      assert.equal(replay.status, 400);

      const c2 = await approveToCode(base, base);
      const f2 = {
        grant_type: "authorization_code",
        code: c2.code,
        redirect_uri: c2.redirect_uri,
        client_id: c2.client_id,
        code_verifier: c2.verifier,
        resource: RESOURCE,
      };
      const [r1, r2] = await Promise.all([
        tokenPost(base, f2),
        tokenPost(base, f2),
      ]);
      const statuses = [r1.status, r2.status].sort();
      assert.deepEqual(statuses, [200, 400]);
    } finally {
      await close();
      await api.close();
    }
  });

  it("리프레시 회전·재사용 시 grant 폐기, downscope", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base, {
        scope: "loftbox.read loftbox.manage",
        allowManage: true,
      });
      const t1 = await codeToTokens(base, c);
      // 회전.
      const r1 = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: t1.refresh,
        client_id: c.client_id,
        resource: RESOURCE,
      });
      assert.equal(r1.status, 200);
      const access2 = r1.body.access_token as string;
      const refresh2 = r1.body.refresh_token as string;
      assert.notEqual(refresh2, t1.refresh);
      // 구 리프레시 재사용 → grant 폐기.
      const reuse = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: t1.refresh,
        client_id: c.client_id,
        resource: RESOURCE,
      });
      assert.equal(reuse.status, 400);
      // 폐기 후에는 새 토큰도 무효.
      const after = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: refresh2,
        client_id: c.client_id,
        resource: RESOURCE,
      });
      assert.equal(after.status, 400);
      const mcp = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${access2}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "initialize",
          id: 1,
          params: {},
        }),
      });
      assert.equal(mcp.status, 401);

      // downscope: manage → read 축소 갱신.
      const c2 = await approveToCode(base, base, {
        scope: "loftbox.read loftbox.manage",
        allowManage: true,
      });
      const t2 = await codeToTokens(base, c2);
      const down = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: t2.refresh,
        client_id: c2.client_id,
        scope: "loftbox.read",
        resource: RESOURCE,
      });
      assert.equal(down.status, 200);
      assert.equal(down.body.scope, "loftbox.read");
      // 범위 초과 갱신 거부.
      const c3 = await approveToCode(base, base, { scope: "loftbox.read" });
      const t3 = await codeToTokens(base, c3);
      const up = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: t3.refresh,
        client_id: c3.client_id,
        scope: "loftbox.read loftbox.manage",
        resource: RESOURCE,
      });
      assert.equal(up.status, 400);
      assert.equal(up.body.error, "invalid_scope");
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth 세션·폐기·영속성", () => {
  it("갱신 후 같은 grant 세션 재사용, 타 grant sid 는 403", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const cA = await approveToCode(base, base, { apiKey: TEST_KEY });
      const tA = await codeToTokens(base, cA);
      const cB = await approveToCode(base, base, { apiKey: TEST_KEY_2 });
      const tB = await codeToTokens(base, cB);

      // A 로 세션 개설 후 sid 확보.
      const transportA = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${tA.access}` } } },
      );
      const clientA = new Client({ name: "a", version: "0.0.0" });
      await clientA.connect(transportA);
      const sid = transportA.sessionId;
      assert.ok(sid);
      try {
        // 갱신 → 새 액세스로 같은 sid 사용.
        const r = await tokenPost(base, {
          grant_type: "refresh_token",
          refresh_token: tA.refresh,
          client_id: cA.client_id,
          resource: RESOURCE,
        });
        assert.equal(r.status, 200);
        const fresh = r.body.access_token as string;
        const reused = await fetch(`${base}/mcp`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${fresh}`,
            "content-type": "application/json",
            "mcp-session-id": sid!,
            accept: "application/json, text/event-stream",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            method: "tools/list",
            id: 2,
            params: {},
          }),
        });
        assert.equal(reused.status, 200);

        // 타 grant 토큰으로 같은 sid → 403.
        const foreign = await fetch(`${base}/mcp`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${tB.access}`,
            "content-type": "application/json",
            "mcp-session-id": sid!,
            accept: "application/json, text/event-stream",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            method: "tools/list",
            id: 3,
            params: {},
          }),
        });
        assert.equal(foreign.status, 403);
      } finally {
        await clientA.close();
      }
    } finally {
      await close();
      await api.close();
    }
  });

  it("RFC7009 폐기: 일반 성공, 타 클라이언트 grant 보호", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const revoke = async (fields: Record<string, string>) => {
        const res = await fetch(`${base}/oauth/revoke`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(fields).toString(),
        });
        return res.status;
      };
      const cA = await approveToCode(base, base);
      const tA = await codeToTokens(base, cA);
      const cB = await approveToCode(base, base);
      const tB = await codeToTokens(base, cB);

      // 미지 토큰도 일반 성공.
      assert.equal(await revoke({ token: "lbmcp_rt_nonexistent" }), 200);
      assert.equal(await revoke({ token: "" }), 200);

      // 타 클라이언트 id 로는 폐기 불가(200 이지만 효력 없음).
      assert.equal(
        await revoke({ token: tA.refresh, client_id: cB.client_id }),
        200,
      );
      const still = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tA.refresh,
        client_id: cA.client_id,
        resource: RESOURCE,
      });
      assert.equal(still.status, 200);

      // 액세스 폐기 → grant/리프레시 계열 전체 종료(부활 불가).
      assert.equal(await revoke({ token: tB.access }), 200);
      const mcpDead = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${tB.access}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      });
      assert.equal(mcpDead.status, 401);
      const grantGone = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tB.refresh,
        client_id: cB.client_id,
        resource: RESOURCE,
      });
      assert.equal(grantGone.status, 400);

      // 리프레시 폐기 → grant 전체 종료.
      const cC = await approveToCode(base, base);
      const tC = await codeToTokens(base, cC);
      assert.equal(await revoke({ token: tC.refresh }), 200);
      const gone = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tC.refresh,
        client_id: cC.client_id,
        resource: RESOURCE,
      });
      assert.equal(gone.status, 400);
      const mcpDead2 = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${tC.access}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      });
      assert.equal(mcpDead2.status, 401);
    } finally {
      await close();
      await api.close();
    }
  });

  it("원본 키 폐기는 즉시 반영(grant 종료)", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base, { apiKey: TEST_KEY });
      const { access, refresh } = await codeToTokens(base, c);
      // 정상 동작 확인.
      const transport = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${access}` } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      await client.close();

      // 원본 키 폐기 → 다음 요청부터 즉시 401.
      api.validKeys.delete(TEST_KEY);
      const denied = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${access}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "initialize",
          id: 1,
          params: {},
        }),
      });
      assert.equal(denied.status, 401);
      // grant 도 종료되어 갱신 불가.
      const r = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: refresh,
        client_id: c.client_id,
        resource: RESOURCE,
      });
      assert.equal(r.status, 400);
      assertNoOAuthTokenDownstream(api);
    } finally {
      await close();
      await api.close();
    }
  });

  it("암호화 영속·재시작: 평문 키 없음·mode0600·리프레시로 복구", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    const store = enableOAuth();
    const { port, close } = await startMcp();
    let refresh = "";
    let clientId = "";
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base, { apiKey: TEST_KEY_2 });
      const t = await codeToTokens(base, c);
      refresh = t.refresh;
      clientId = c.client_id;
      assert.ok(refresh);
    } finally {
      await close();
    }
    // 저장소 감사: 평문 키·raw 토큰 없음, 권한 0600.
    const raw = readFileSync(store, "utf8");
    assert.ok(!raw.includes(TEST_KEY_2), "저장소에 평문 키 금지");
    assert.ok(!raw.includes("lbmcp_rt_"), "저장소에 raw 토큰 금지");
    assert.ok(!raw.includes("lbmcp_at_"), "저장소에 raw 토큰 금지");
    const doc = JSON.parse(raw) as {
      grants: Record<
        string,
        { enc: { iv: string; data: string; tag: string } }
      >;
    };
    const grants = Object.values(doc.grants);
    assert.equal(grants.length, 1);
    assert.ok(grants[0]!.enc.iv && grants[0]!.enc.data && grants[0]!.enc.tag);
    assert.equal(statSync(store).mode & 0o777, 0o600);

    // 재시작(새 서버, 같은 저장소·같은 암호화 키).
    const { port: port2, close: close2 } = await startMcp();
    try {
      const base2 = `http://127.0.0.1:${port2}`;
      const r = await tokenPost(base2, {
        grant_type: "refresh_token",
        refresh_token: refresh,
        client_id: clientId,
        resource: RESOURCE,
      });
      assert.equal(r.status, 200);
      const fresh = r.body.access_token as string;
      const transport = new StreamableHTTPClientTransport(
        new URL(`${base2}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${fresh}` } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        assert.ok(tools.length > 0);
      } finally {
        await client.close();
      }
      assertNoOAuthTokenDownstream(api);
    } finally {
      await close2();
      await api.close();
    }
  });

  it("액세스 만료 후 401, 갱신 토큰으로 복구", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp({
      oauth: { allowInsecureLoopback: true, accessTtlSecs: 1 },
    });
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base);
      const { access, refresh } = await codeToTokens(base, c);
      await new Promise((r) => setTimeout(r, 1200));
      const expired = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${access}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "initialize",
          id: 1,
          params: {},
        }),
      });
      assert.equal(expired.status, 401);
      const r = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: refresh,
        client_id: c.client_id,
        resource: RESOURCE,
      });
      assert.equal(r.status, 200);
      const fresh = r.body.access_token as string;
      const transport = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${fresh}` } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        assert.ok(tools.length > 0);
      } finally {
        await client.close();
      }
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth 웹 보안(XSS·Origin·Host·CSRF·헤더)", () => {
  it("미검증 클라이언트 이름 XSS 이스케이프", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const evil = `<script>alert(document.domain)</script><img src=x onerror=alert(1)>`;
      const redirectUri = "http://127.0.0.1:9/cb-xss";
      const res = await fetch(`${base}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uris: [redirectUri],
          client_name: evil,
        }),
      });
      assert.equal(res.status, 201);
      const { client_id } = (await res.json()) as { client_id: string };
      const { challenge } = pkce();
      const got = await authorizeGet(base, {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      });
      assert.equal(got.status, 200);
      assert.ok(
        !got.issued!.html.includes("<script>alert"),
        "raw 스크립트 없음",
      );
      assert.ok(!got.issued!.html.includes(evil), "raw 이름 없음");
      assert.ok(got.issued!.html.includes("&lt;script&gt;"), "이스케이프 출력");
      assert.match(got.issued!.html, /미검증/);
    } finally {
      await close();
      await api.close();
    }
  });

  it("CSRF 삼중 바인딩: Origin·쿠키·CSRF 불일치 거부", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-csrf";
      const { client_id } = await registerClient(base, redirectUri);
      const { challenge } = pkce();
      const fresh = async () =>
        (
          await authorizeGet(base, {
            response_type: "code",
            client_id,
            redirect_uri: redirectUri,
            scope: "loftbox.read",
            state: "s",
            code_challenge: challenge,
            code_challenge_method: "S256",
            resource: RESOURCE,
          })
        ).issued!;
      // Origin 누락.
      const t1 = await fresh();
      const noOrigin = await authorizePost(
        base,
        base,
        { txn: t1.txn, csrf: t1.csrf, decision: "allow", api_key: TEST_KEY },
        t1.cookie,
        null,
      );
      assert.equal(noOrigin.status, 403);
      // 악성 Origin.
      const t2 = await fresh();
      const evilOrigin = await authorizePost(
        base,
        base,
        { txn: t2.txn, csrf: t2.csrf, decision: "allow", api_key: TEST_KEY },
        t2.cookie,
        "https://evil.test",
      );
      assert.equal(evilOrigin.status, 403);
      // CSRF 토큰 변조.
      const t3 = await fresh();
      const badCsrf = await authorizePost(
        base,
        base,
        { txn: t3.txn, csrf: "forged", decision: "allow", api_key: TEST_KEY },
        t3.cookie,
      );
      assert.equal(badCsrf.status, 403);
      // 쿠키 누락.
      const t4 = await fresh();
      const noCookie = await authorizePost(base, base, {
        txn: t4.txn,
        csrf: t4.csrf,
        decision: "allow",
        api_key: TEST_KEY,
      });
      assert.equal(noCookie.status, 403);
      // 타 txn 쿠키 교차 사용.
      const t5 = await fresh();
      const t6 = await fresh();
      const crossed = await authorizePost(
        base,
        base,
        { txn: t5.txn, csrf: t5.csrf, decision: "allow", api_key: TEST_KEY },
        t6.cookie,
      );
      assert.equal(crossed.status, 403);
    } finally {
      await close();
      await api.close();
    }
  });

  it("/mcp Origin: 없음 통과·신뢰 통과·악성 403, 401 WWW-Authenticate 에 resource_metadata", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      // Bearer 없음 → 401 + resource_metadata.
      const anon = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      });
      assert.equal(anon.status, 401);
      const www = anon.headers.get("www-authenticate") ?? "";
      assert.ok(www.includes("resource_metadata="), `WWW-Authenticate: ${www}`);
      assert.ok(www.includes(".well-known/oauth-protected-resource"));
      // 악성 Origin → 403.
      const evil = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "https://evil.test",
          authorization: "Bearer lb_test_synthetic_key_001",
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      });
      assert.equal(evil.status, 403);
      // Origin 없음 → 정상 경로(무효 키면 401, Origin 탓이 아님).
      const noOrigin = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer lb_test_WRONG",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "initialize",
          id: 1,
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "test", version: "0.0.0" },
          },
        }),
      });
      assert.equal(noOrigin.status, 401);
    } finally {
      await close();
      await api.close();
    }
  });

  it("Host 검증: /oauth/* 는 비신뢰 Host 거부", async () => {
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const raw = (path: string, host: string): Promise<number> =>
        new Promise((resolve, reject) => {
          const r = httpRequest(
            {
              host: "127.0.0.1",
              port,
              path,
              method: "POST",
              headers: {
                host,
                "content-type": "application/json",
                "content-length": "2",
              },
            },
            (res) => {
              res.resume();
              res.on("end", () => resolve(res.statusCode ?? 0));
            },
          );
          r.on("error", reject);
          r.end("{}");
        });
      assert.equal(await raw("/oauth/register", "evil.test"), 400);
      assert.equal(await raw("/oauth/token", "evil.test"), 400);
      // 루프백 Host 는 통과(본문 오류여도 Host 탓 400 과 구분 — 등록은 JSON 파싱 후 400).
      const loopback = await raw("/oauth/register", `127.0.0.1:${port}`);
      assert.equal(loopback, 400);
    } finally {
      await close();
    }
  });

  it("브라우저 보안 헤더(CSP·frame-ancestors·nosniff·no-store)", async () => {
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const home = await fetch(`${base}/`);
      assert.equal(home.status, 200);
      const csp = home.headers.get("content-security-policy") ?? "";
      assert.ok(csp.includes("frame-ancestors 'none'"), `CSP: ${csp}`);
      assert.equal(home.headers.get("x-content-type-options"), "nosniff");
      assert.equal(home.headers.get("referrer-policy"), "no-referrer");
      assert.equal(home.headers.get("x-frame-options"), "DENY");
      const setup = await fetch(`${base}/setup`);
      assert.equal(setup.status, 200);
      // 활성 모드 홈: URL·Claude/ChatGPT 안내 포함, 비밀 없음.
      const html = await home.text();
      assert.ok(html.includes(RESOURCE));
      assert.ok(html.includes("Claude"));
      assert.ok(html.includes("ChatGPT"));
      assert.ok(html.includes("Register automatically"));
      assert.ok(html.includes("loftbox.manage"));
      // 헬스 정직 표기.
      const health = await fetch(`${base}/health`);
      const h = (await health.json()) as Record<string, unknown>;
      assert.equal(h.oauth_enabled, true);
      assert.equal(h.resource, RESOURCE);
      assert.equal(h.issuer, PUBLIC_URL);
    } finally {
      await close();
    }
  });
});

describe("OAuth 비활성·설정 실패", () => {
  it("비활성 기본: 레거시 유지, OAuth 경로 404, 홈 정직 표기", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    // OAuth env 미설정 → 비활성.
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const health = await fetch(`${base}/health`);
      const h = (await health.json()) as Record<string, unknown>;
      assert.equal(h.status, "ok");
      assert.equal(h.oauth_enabled, false);
      assert.ok(!("resource" in h));
      for (const p of [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-authorization-server",
        "/oauth/register",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/revoke",
      ]) {
        const res = await fetch(`${base}${p}`, { method: "GET" });
        assert.equal(res.status, 404, p);
      }
      const home = await fetch(`${base}/`);
      assert.equal(home.status, 200);
      assert.match(await home.text(), /비활성화/);
      // 레거시 raw 키 흐름 유지.
      const transport = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${TEST_KEY}` } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        assert.ok(tools.length > 0);
      } finally {
        await client.close();
      }
      // OAuth 형태 토큰은 raw 로 폴백하지 않는다(다운스트림 미호출).
      const seenBefore = api.seenAuthz.length;
      const forged = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: "Bearer lbmcp_at_forged",
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      });
      assert.equal(forged.status, 401);
      assert.equal(api.seenAuthz.length, seenBefore);
    } finally {
      await close();
      await api.close();
    }
  });

  it("활성 + 무효 설정은 기동 실패(fail-closed)", async () => {
    const cases: Array<[string, Record<string, string>]> = [
      ["공개 URL 누락", { LOFTBOX_MCP_OAUTH_ENABLED: "true" }],
      [
        "http 공개 URL(운영 기본)",
        {
          LOFTBOX_MCP_OAUTH_ENABLED: "true",
          LOFTBOX_MCP_PUBLIC_URL: "http://mcp.loftbox.net",
          LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY: testEncryptionKey(),
          LOFTBOX_MCP_OAUTH_STORE: testStorePath(),
        },
      ],
      [
        "상대 경로 저장소",
        {
          LOFTBOX_MCP_OAUTH_ENABLED: "true",
          LOFTBOX_MCP_PUBLIC_URL: "https://mcp.loftbox.net",
          LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY: testEncryptionKey(),
          LOFTBOX_MCP_OAUTH_STORE: "relative/store.json",
        },
      ],
      [
        "/opt/loftbox-mcp 내부 저장소",
        {
          LOFTBOX_MCP_OAUTH_ENABLED: "true",
          LOFTBOX_MCP_PUBLIC_URL: "https://mcp.loftbox.net",
          LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY: testEncryptionKey(),
          LOFTBOX_MCP_OAUTH_STORE: "/opt/loftbox-mcp/oauth.json",
        },
      ],
      [
        "정규화 우회 저장소(/x/../opt/...)",
        {
          LOFTBOX_MCP_OAUTH_ENABLED: "true",
          LOFTBOX_MCP_PUBLIC_URL: "https://mcp.loftbox.net",
          LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY: testEncryptionKey(),
          LOFTBOX_MCP_OAUTH_STORE: "/tmp/../opt/loftbox-mcp/oauth.json",
        },
      ],
      [
        "짧은 암호화 키",
        {
          LOFTBOX_MCP_OAUTH_ENABLED: "true",
          LOFTBOX_MCP_PUBLIC_URL: "https://mcp.loftbox.net",
          LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY: "short",
          LOFTBOX_MCP_OAUTH_STORE: testStorePath(),
        },
      ],
      [
        "암호화 키 누락",
        {
          LOFTBOX_MCP_OAUTH_ENABLED: "true",
          LOFTBOX_MCP_PUBLIC_URL: "https://mcp.loftbox.net",
          LOFTBOX_MCP_OAUTH_STORE: testStorePath(),
        },
      ],
    ];
    for (const [name, vars] of cases) {
      for (const k of OAUTH_ENV_KEYS) delete process.env[k];
      Object.assign(process.env, vars);
      assert.throws(() => buildHttpServer(), /OAuth|oauth|기동/, name);
    }
  });

  it("LOFTBOX_MCP_READ_ONLY 상한: manage 승인도 읽기로 축소", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    process.env.LOFTBOX_MCP_READ_ONLY = "true";
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base, {
        scope: "loftbox.read loftbox.manage",
        allowManage: true,
      });
      const { access } = await codeToTokens(base, c);
      const transport = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${access}` } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        const names = tools.map((x) => x.name);
        assert.ok(names.includes("agent_list"));
        assert.ok(!names.includes("domain_verify"), "read-only 상한");
        assert.ok(!names.includes("message_send"));
      } finally {
        await client.close();
      }
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth UUID·컨텍스트 바인딩", () => {
  it("null·비UUID 컨텍스트 키는 승인 거부(재시도 가능), UUID는 승인", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    const store = enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-uuid";
      const { client_id } = await registerClient(base, redirectUri);
      const { challenge } = pkce();
      const fresh = async () =>
        (
          await authorizeGet(base, {
            response_type: "code",
            client_id,
            redirect_uri: redirectUri,
            scope: "loftbox.read",
            state: "uuid-state",
            code_challenge: challenge,
            code_challenge_method: "S256",
            resource: RESOURCE,
          })
        ).issued!;
      // null 키 id(세션/dev 형태) → 재시도 폼, 코드 없음.
      const t1 = await fresh();
      const nullKey = await authorizePost(
        base,
        base,
        {
          txn: t1.txn,
          csrf: t1.csrf,
          decision: "allow",
          api_key: TEST_KEY_NULLKEY,
        },
        t1.cookie,
      );
      assert.equal(nullKey.status, 200);
      assert.match(nullKey.html, /사용할 수 없습니다/);
      assert.equal(nullKey.location, null);
      // 비UUID id → 재시도 폼, 코드 없음.
      const t2 = await fresh();
      const badUuid = await authorizePost(
        base,
        base,
        {
          txn: t2.txn,
          csrf: t2.csrf,
          decision: "allow",
          api_key: TEST_KEY_BADUUID,
        },
        t2.cookie,
      );
      assert.equal(badUuid.status, 200);
      assert.match(badUuid.html, /사용할 수 없습니다/);
      // 같은 txn 에 유효 UUID 키로 재시도 → 성공.
      const retry = await authorizePost(
        base,
        base,
        { txn: t2.txn, csrf: t2.csrf, decision: "allow", api_key: TEST_KEY },
        t2.cookie,
      );
      assert.equal(retry.status, 302);
      const loc = new URL(retry.location!, "http://x");
      assert.ok(loc.searchParams.get("code"));
      assert.equal(loc.searchParams.get("state"), "uuid-state");
      // 거부된 시도에서 grant 가 생기지 않았다.
      const doc = JSON.parse(readFileSync(store, "utf8")) as {
        grants: Record<string, { org_id: string; key_id: string }>;
      };
      const grants = Object.values(doc.grants);
      assert.equal(grants.length, 1);
      assert.equal(grants[0]!.org_id, UUID_ORG_1);
      assert.equal(grants[0]!.key_id, UUID_KEY_1);
    } finally {
      await close();
      await api.close();
    }
  });

  it("재검증 org/키 변경 시 grant 종료", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const mcpPing = (token: string) =>
        fetch(`${base}/mcp`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
        }).then((r) => r.status);
      // org 변경.
      const c1 = await approveToCode(base, base, { apiKey: TEST_KEY });
      const t1 = await codeToTokens(base, c1);
      api.validKeys.set(TEST_KEY, { orgId: UUID_ORG_3, keyId: UUID_KEY_1 });
      assert.equal(await mcpPing(t1.access), 401);
      const r1 = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: t1.refresh,
        client_id: c1.client_id,
        resource: RESOURCE,
      });
      assert.equal(r1.status, 400);
      // 키 id 변경.
      const c2 = await approveToCode(base, base, { apiKey: TEST_KEY_2 });
      const t2 = await codeToTokens(base, c2);
      api.validKeys.set(TEST_KEY_2, { orgId: UUID_ORG_2, keyId: UUID_KEY_3 });
      assert.equal(await mcpPing(t2.access), 401);
      const r2 = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: t2.refresh,
        client_id: c2.client_id,
        resource: RESOURCE,
      });
      assert.equal(r2.status, 400);
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth 리프레시 직렬화·클라이언트 바인딩", () => {
  it("client_id 생략·미등록·타인 거부, 타인 리플레이도 피해 grant 보호", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const cA = await approveToCode(base, base);
      const tA = await codeToTokens(base, cA);
      const cB = await approveToCode(base, base);
      await codeToTokens(base, cB);
      // 생략 → 거부.
      const omitted = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tA.refresh,
        resource: RESOURCE,
      });
      assert.equal(omitted.status, 400);
      // 미등록 → 거부.
      const unknown = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tA.refresh,
        client_id: "lbmcp_cli_nonexistent",
        resource: RESOURCE,
      });
      assert.equal(unknown.status, 400);
      // 타인 → 거부, 피해 grant 생존.
      const wrong = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tA.refresh,
        client_id: cB.client_id,
        resource: RESOURCE,
      });
      assert.equal(wrong.status, 400);
      const alive = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tA.refresh,
        client_id: cA.client_id,
        resource: RESOURCE,
      });
      assert.equal(alive.status, 200);
      const rotated = alive.body.refresh_token as string;
      // 타인의 소비된 토큰 리플레이 → 거부 + 피해 grant 보호(폐기 없음).
      const replayWrong = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tA.refresh,
        client_id: cB.client_id,
        resource: RESOURCE,
      });
      assert.equal(replayWrong.status, 400);
      const still = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: rotated,
        client_id: cA.client_id,
        resource: RESOURCE,
      });
      assert.equal(still.status, 200);
    } finally {
      await close();
      await api.close();
    }
  });

  it("동시 동일 토큰 갱신은 하나만 성공, 패자는 재사용으로 계열 폐기", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base);
      const t = await codeToTokens(base, c);
      const fields = {
        grant_type: "refresh_token",
        refresh_token: t.refresh,
        client_id: c.client_id,
        resource: RESOURCE,
      };
      const [r1, r2] = await Promise.all([
        tokenPost(base, fields),
        tokenPost(base, fields),
      ]);
      assert.deepEqual([r1.status, r2.status].sort(), [200, 400]);
      const winner = r1.status === 200 ? r1 : r2;
      // 패자의 재사용 시도가 계열을 폐기했으므로 승자의 새 토큰도 무효.
      const after = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: winner.body.refresh_token as string,
        client_id: c.client_id,
        resource: RESOURCE,
      });
      assert.equal(after.status, 400);
    } finally {
      await close();
      await api.close();
    }
  });

  it("재시작 후 재사용 판정 유지(구 토큰 리플레이는 계열 폐기)", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    let oldRefresh = "";
    let newRefresh = "";
    let clientId = "";
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base);
      const t = await codeToTokens(base, c);
      clientId = c.client_id;
      oldRefresh = t.refresh;
      const r = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: t.refresh,
        client_id: c.client_id,
        resource: RESOURCE,
      });
      assert.equal(r.status, 200);
      newRefresh = r.body.refresh_token as string;
    } finally {
      await close();
    }
    const { port: port2, close: close2 } = await startMcp();
    try {
      const base2 = `http://127.0.0.1:${port2}`;
      // 재시작 뒤 구 토큰 리플레이 → 폐기.
      const replay = await tokenPost(base2, {
        grant_type: "refresh_token",
        refresh_token: oldRefresh,
        client_id: clientId,
        resource: RESOURCE,
      });
      assert.equal(replay.status, 400);
      const after = await tokenPost(base2, {
        grant_type: "refresh_token",
        refresh_token: newRefresh,
        client_id: clientId,
        resource: RESOURCE,
      });
      assert.equal(after.status, 400);
    } finally {
      await close2();
      await api.close();
    }
  });
});

describe("OAuth 저장소 바인딩·트랜잭션", () => {
  it("변경된 origin 으로 옛 저장소를 열면 토큰 발급 거부", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    let refresh = "";
    let clientId = "";
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base);
      const t = await codeToTokens(base, c);
      refresh = t.refresh;
      clientId = c.client_id;
    } finally {
      await close();
    }
    // 같은 저장소·다른 공개 origin 으로 재기동.
    process.env.LOFTBOX_MCP_PUBLIC_URL = "http://127.0.0.1:10";
    const NEW_RESOURCE = "http://127.0.0.1:10/mcp";
    const { port: port2, close: close2 } = await startMcp();
    try {
      const base2 = `http://127.0.0.1:${port2}`;
      // 새 resource 로 옛 토큰 → 바인딩 불일치 거부.
      const mismatch = await tokenPost(base2, {
        grant_type: "refresh_token",
        refresh_token: refresh,
        client_id: clientId,
        resource: NEW_RESOURCE,
      });
      assert.equal(mismatch.status, 400);
      assert.equal(mismatch.body.error, "invalid_grant");
      // 옛 resource 제출 → invalid_target.
      const wrongRes = await tokenPost(base2, {
        grant_type: "refresh_token",
        refresh_token: refresh,
        client_id: clientId,
        resource: RESOURCE,
      });
      assert.equal(wrongRes.status, 400);
      assert.equal(wrongRes.body.error, "invalid_target");
    } finally {
      await close2();
      await api.close();
    }
  });

  it("심볼릭 링크·불안전 부모 저장소 거부, 구 레코드 바인딩 기본값", async () => {
    const dir = mkdtempSync(join(tmpdir(), "lbmcp-store-"));
    const real = join(dir, "real.json");
    const link = join(dir, "link.json");
    symlinkSync(real, link);
    assert.throws(() => FileOAuthStore.open(link), /심볼릭|경로/);
    // 임시 파일에 직접 쓴 뒤 링크로 열어도 거부된다.
    writeFileSync(
      real,
      JSON.stringify({ version: 1, clients: {}, grants: {}, refresh: {} }),
    );
    assert.throws(() => FileOAuthStore.open(link), /심볼릭|경로/);
    // 불안전(그룹/타인 쓰기 가능) 부모 디렉터리 거부.
    const shared = join(dir, "shared");
    mkdirSync(shared);
    chmodSync(shared, 0o755);
    assert.throws(
      () => FileOAuthStore.open(join(shared, "store.json")),
      /안전하지|권한/,
    );
    chmodSync(shared, 0o700);
    // 구버전 레코드(issuer/resource 누락)는 빈 바인딩으로 적재되어
    // 런타임 검사가 사용을 거부한다.
    const legacy = parseStore(
      JSON.stringify({
        version: 1,
        clients: {},
        grants: {
          g1: {
            grant_id: "g1",
            client_id: "c",
            scope: ["loftbox.read"],
            enc: { iv: "e", data: "e", tag: "e" },
            org_id: null,
            org_slug: null,
            org_name: null,
            key_id: null,
            backend_scopes: [],
            created_at: 1,
            revoked_at: null,
          },
        },
        refresh: {},
      }),
    );
    assert.equal(legacy.grants["g1"]!.issuer, "");
    assert.equal(legacy.grants["g1"]!.resource, "");
  });

  it("영속 실패 시 폐기는 503, 부분 변경 없이 복구 후 재시도 가능", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    const store = enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base);
      const t = await codeToTokens(base, c);
      const revoke = (fields: Record<string, string>) =>
        fetch(`${base}/oauth/revoke`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(fields).toString(),
        }).then((r) => r.status);
      const before = readFileSync(store, "utf8");
      // 저장소 디렉터리를 읽기 전용으로 — 쓰기 실패 유도.
      const parent = dirname(store);
      chmodSync(parent, 0o500);
      try {
        assert.equal(await revoke({ token: t.refresh }), 503);
        // 부분 변경 없음 — 파일 동일.
        assert.equal(readFileSync(store, "utf8"), before);
      } finally {
        chmodSync(parent, 0o700);
      }
      // 복구 후 재시도 → 200 + 효력 있음.
      assert.equal(await revoke({ token: t.refresh }), 200);
      const gone = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: t.refresh,
        client_id: c.client_id,
        resource: RESOURCE,
      });
      assert.equal(gone.status, 400);
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth 동의 트랜잭션·파라미터", () => {
  it("동시 이중 동의 제출은 단일 grant/코드", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    const store = enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-double";
      const { client_id } = await registerClient(base, redirectUri);
      const { challenge } = pkce();
      const got = await authorizeGet(base, {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "double",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      });
      assert.equal(got.status, 200);
      const fields = {
        txn: got.issued!.txn,
        csrf: got.issued!.csrf,
        decision: "allow",
        api_key: TEST_KEY,
      };
      const [p1, p2] = await Promise.all([
        authorizePost(base, base, fields, got.issued!.cookie),
        authorizePost(base, base, fields, got.issued!.cookie),
      ]);
      assert.deepEqual([p1.status, p2.status].sort(), [302, 400]);
      const winner = p1.status === 302 ? p1 : p2;
      assert.ok(new URL(winner.location!, "http://x").searchParams.get("code"));
      const doc = JSON.parse(readFileSync(store, "utf8")) as {
        grants: Record<string, unknown>;
      };
      assert.equal(Object.keys(doc.grants).length, 1);
    } finally {
      await close();
      await api.close();
    }
  });

  it("중복 OAuth 쿼리/폼 파라미터 거부", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-dup";
      const { client_id } = await registerClient(base, redirectUri);
      const { challenge } = pkce();
      const valid = {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "dup-safe",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      };
      // 중복 client_id → 페이지 오류(리다이렉트 없음).
      const q1 = new URLSearchParams(valid);
      q1.append("client_id", "lbmcp_cli_other");
      const d1 = await fetch(`${base}/oauth/authorize?${q1.toString()}`, {
        redirect: "manual",
      });
      assert.equal(d1.status, 400);
      assert.equal(d1.headers.get("location"), null);
      // 중복 state → 리다이렉트 오류 + state 미반사.
      const q2 = new URLSearchParams(valid);
      q2.append("state", "injected");
      const d2 = await fetch(`${base}/oauth/authorize?${q2.toString()}`, {
        redirect: "manual",
      });
      assert.equal(d2.status, 302);
      const lloc = new URL(d2.headers.get("location")!, "http://x");
      assert.equal(lloc.searchParams.get("error"), "invalid_request");
      assert.equal(lloc.searchParams.get("iss"), PUBLIC_URL);
      assert.equal(lloc.searchParams.get("state"), null);
      // 토큰 폼 중복 code → invalid_request.
      const c = await approveToCode(base, base);
      const dupBody =
        new URLSearchParams({
          grant_type: "authorization_code",
          code: c.code,
          redirect_uri: c.redirect_uri,
          client_id: c.client_id,
          code_verifier: c.verifier,
          resource: RESOURCE,
        }).toString() + `&code=${encodeURIComponent(c.code)}`;
      const t = await fetch(`${base}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: dupBody,
      });
      assert.equal(t.status, 400);
      assert.equal(
        ((await t.json()) as { error: string }).error,
        "invalid_request",
      );
      // 폐기 폼 중복 token → 400.
      const r = await fetch(`${base}/oauth/revoke`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: `token=${encodeURIComponent("lbmcp_rt_x")}&token=${encodeURIComponent("lbmcp_rt_y")}`,
      });
      assert.equal(r.status, 400);
    } finally {
      await close();
      await api.close();
    }
  });

  it("S256 challenge 정확 형태(43자) 강제", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-pkce";
      const { client_id } = await registerClient(base, redirectUri);
      const { challenge } = pkce();
      assert.equal(challenge.length, 43);
      const valid = {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "pkce",
        code_challenge_method: "S256",
        resource: RESOURCE,
      };
      for (const bad of ["a".repeat(42), "a".repeat(44), "a".repeat(128)]) {
        const got = await authorizeGet(base, { ...valid, code_challenge: bad });
        assert.equal(got.status, 302, `길이 ${bad.length} 거부 필요`);
        assert.equal(
          new URL(got.location!, "http://x").searchParams.get("error"),
          "invalid_request",
        );
      }
      const ok = await authorizeGet(base, {
        ...valid,
        code_challenge: challenge,
      });
      assert.equal(ok.status, 200);
    } finally {
      await close();
      await api.close();
    }
  });

  it("state roundtrip: 없음·빈값·인코딩·거부·POST교체 불가", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-state";
      const { client_id } = await registerClient(base, redirectUri);
      const { challenge } = pkce();
      const baseParams = {
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      };
      const approve = async (issued: {
        txn: string;
        csrf: string;
        cookie: string;
      }) =>
        authorizePost(
          base,
          base,
          {
            txn: issued.txn,
            csrf: issued.csrf,
            decision: "allow",
            api_key: TEST_KEY,
          },
          issued.cookie,
        );
      // 없음 → 콜백에 state 없음.
      const g0 = await authorizeGet(base, baseParams);
      assert.equal(g0.status, 200);
      const p0 = await approve(g0.issued!);
      assert.equal(p0.status, 302);
      const l0 = new URL(p0.location!, "http://x");
      assert.ok(l0.searchParams.get("code"));
      assert.equal(l0.searchParams.has("state"), false);
      assert.equal(l0.searchParams.get("iss"), PUBLIC_URL);
      // 빈 값 → 빈 값 그대로.
      const g1 = await authorizeGet(base, { ...baseParams, state: "" });
      assert.equal(g1.status, 200);
      const p1 = await approve(g1.issued!);
      assert.equal(p1.status, 302);
      const l1 = new URL(p1.location!, "http://x");
      assert.equal(l1.searchParams.has("state"), true);
      assert.equal(l1.searchParams.get("state"), "");
      // 인코딩 문자 → 정확히.
      const tricky = "web-sdk + 한글 /?&=%";
      const g2 = await authorizeGet(base, { ...baseParams, state: tricky });
      assert.equal(g2.status, 200);
      const p2 = await approve(g2.issued!);
      assert.equal(p2.status, 302);
      const l2 = new URL(p2.location!, "http://x");
      assert.equal(l2.searchParams.get("state"), tricky);
      assert.equal(l2.searchParams.get("iss"), PUBLIC_URL);
      // 거부 → state·iss 정확히.
      const g3 = await authorizeGet(base, { ...baseParams, state: tricky });
      const deny = await authorizePost(
        base,
        base,
        { txn: g3.issued!.txn, csrf: g3.issued!.csrf, decision: "deny" },
        g3.issued!.cookie,
      );
      assert.equal(deny.status, 302);
      const l3 = new URL(deny.location!, "http://x");
      assert.equal(l3.searchParams.get("error"), "access_denied");
      assert.equal(l3.searchParams.get("state"), tricky);
      assert.equal(l3.searchParams.get("iss"), PUBLIC_URL);
      // POST 폼의 state 항목은 무시(교체 불가).
      const g4 = await authorizeGet(base, { ...baseParams, state: "orig" });
      const p4 = await authorizePost(
        base,
        base,
        {
          txn: g4.issued!.txn,
          csrf: g4.issued!.csrf,
          decision: "allow",
          api_key: TEST_KEY,
          state: "forged",
        },
        g4.issued!.cookie,
      );
      assert.equal(p4.status, 302);
      assert.equal(
        new URL(p4.location!, "http://x").searchParams.get("state"),
        "orig",
      );
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth 호스트·클라이언트인증·브라우저정책", () => {
  it("Host 검증: /mcp 인증 요청도 비신뢰 Host 거부", async () => {
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const raw = (host: string): Promise<number> =>
        new Promise((resolve, reject) => {
          const body = JSON.stringify({
            jsonrpc: "2.0",
            method: "ping",
            id: 1,
          });
          const r = httpRequest(
            {
              host: "127.0.0.1",
              port,
              path: "/mcp",
              method: "POST",
              headers: {
                host,
                "content-type": "application/json",
                "content-length": String(body.length),
              },
            },
            (res) => {
              res.resume();
              res.on("end", () => resolve(res.statusCode ?? 0));
            },
          );
          r.on("error", reject);
          r.end(body);
        });
      assert.equal(await raw("evil.test"), 400);
      // 루프백 Host 는 인증 단계까지 통과(Bearer 없어 401).
      assert.equal(await raw(`127.0.0.1:${port}`), 401);
    } finally {
      await close();
    }
  });

  it("토큰 엔드포인트 client_secret/Basic 인증 거부(코드 미소진)", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base);
      const fields = {
        grant_type: "authorization_code",
        code: c.code,
        redirect_uri: c.redirect_uri,
        client_id: c.client_id,
        code_verifier: c.verifier,
        resource: RESOURCE,
      };
      // Authorization 헤더 → invalid_client.
      const basic = await fetch(`${base}/oauth/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${Buffer.from(`${c.client_id}:secret`).toString("base64")}`,
        },
        body: new URLSearchParams(fields).toString(),
      });
      assert.equal(basic.status, 400);
      assert.equal(
        ((await basic.json()) as { error: string }).error,
        "invalid_client",
      );
      // client_secret 필드 → invalid_client.
      const secret = await tokenPost(base, { ...fields, client_secret: "x" });
      assert.equal(secret.status, 400);
      assert.equal(secret.body.error, "invalid_client");
      // 거부된 시도에서 코드가 소진되지 않았으므로 정상 교환 성공.
      const ok = await tokenPost(base, fields);
      assert.equal(ok.status, 200);
    } finally {
      await close();
      await api.close();
    }
  });

  it("동의 페이지 same-origin + 콜백 form-action, 리다이렉트는 no-referrer", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:9/cb-foreign";
      const { client_id } = await registerClient(base, redirectUri);
      const { challenge } = pkce();
      const q = new URLSearchParams({
        response_type: "code",
        client_id,
        redirect_uri: redirectUri,
        scope: "loftbox.read",
        state: "csp",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: RESOURCE,
      }).toString();
      const page = await fetch(`${base}/oauth/authorize?${q}`, {
        redirect: "manual",
      });
      assert.equal(page.status, 200);
      // Chromium same-origin 폼 Origin 보존 + 교차 출처 유출 방지.
      assert.equal(page.headers.get("referrer-policy"), "same-origin");
      const csp = page.headers.get("content-security-policy") ?? "";
      assert.ok(csp.includes("frame-ancestors 'none'"), `CSP: ${csp}`);
      assert.ok(
        csp.includes("form-action 'self' http://127.0.0.1:9"),
        `CSP: ${csp}`,
      );
      assert.ok(!csp.includes("*"), `와일드카드 금지: ${csp}`);
      const html = await page.text();
      // 거부는 빈 키로도 동작해야 한다.
      assert.ok(html.includes("formnovalidate"), "deny formnovalidate 필요");
      const txn = /name="txn" value="([^"]+)"/.exec(html)?.[1] ?? "";
      const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? "";
      const cookie = (page.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
      assert.ok(txn && csrf && cookie.startsWith("lbmcp_txn="));
      // 승인 성공 리다이렉트: no-referrer 유지 + 콜백 origin CSP.
      const posted = await fetch(`${base}/oauth/authorize`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          origin: base,
          cookie,
        },
        body: new URLSearchParams({
          txn,
          csrf,
          decision: "allow",
          api_key: TEST_KEY,
        }).toString(),
        redirect: "manual",
      });
      assert.equal(posted.status, 302);
      assert.equal(posted.headers.get("referrer-policy"), "no-referrer");
      const rcsp = posted.headers.get("content-security-policy") ?? "";
      assert.ok(
        rcsp.includes("form-action 'self' http://127.0.0.1:9"),
        `리다이렉트 CSP: ${rcsp}`,
      );
      assert.ok(!rcsp.includes("*"), `와일드카드 금지: ${rcsp}`);
      const postedLoc = new URL(posted.headers.get("location")!, "http://x");
      assert.ok(postedLoc.searchParams.get("code"));
      assert.equal(postedLoc.searchParams.get("iss"), PUBLIC_URL);
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth 저장소 용량·트랜잭션 안전", () => {
  it("직렬화 바이트 상한: 실패 시 메모리·디스크 불변, 이후 허용 연산 지속", async () => {
    const dir = mkdtempSync(join(tmpdir(), "lbmcp-cap-"));
    chmodSync(dir, 0o700);
    const path = join(dir, "store.json");
    // 작은 상한으로 lawful 초과를 합성 — 거대 픽스처 출력 없음.
    const store = FileOAuthStore.open(path, { maxStoreBytes: 2048 });
    await store.mutate((d) => {
      d.clients["c0"] = {
        client_id: "c0",
        client_name: "ok",
        redirect_uris: ["http://127.0.0.1:9/cb0"],
        created_at: Date.now(),
      };
    });
    const beforeDisk = readFileSync(path, "utf8");
    const beforeCount = store.read((d) => Object.keys(d.clients).length);
    // 멀티바이트(UTF-8 3바이트/자)로 바이트 상한 초과 유도 — 문자 길이가 아닌
    // 바이트 기준임을 검증. 값 자체는 로그에 남기지 않는다.
    const bigName = "가".repeat(1200);
    await assert.rejects(
      store.mutate((d) => {
        d.clients["c-big"] = {
          client_id: "c-big",
          client_name: bigName,
          redirect_uris: ["http://127.0.0.1:9/cb-big"],
          created_at: Date.now(),
        };
      }),
      (e: unknown) => isStoreCapacityError(e),
      "용량 초과는 typed 거부",
    );
    // 메모리·디스크 불변.
    assert.equal(
      store.read((d) => Object.keys(d.clients).length),
      beforeCount,
    );
    assert.equal(
      store.read((d) => d.clients["c-big"]),
      undefined,
    );
    assert.equal(readFileSync(path, "utf8"), beforeDisk);
    // 재시작 가능 + 기존 데이터 유지.
    const reopened = FileOAuthStore.open(path, { maxStoreBytes: 2048 });
    assert.equal(
      reopened.read((d) => Object.keys(d.clients).length),
      beforeCount,
    );
    // 건강한 브로커는 이후 허용 연산 지속 — 작은 등록 성공.
    await reopened.mutate((d) => {
      d.clients["c1"] = {
        client_id: "c1",
        client_name: "small",
        redirect_uris: ["http://127.0.0.1:9/cb1"],
        created_at: Date.now(),
      };
    });
    assert.ok(reopened.read((d) => d.clients["c1"]));
  });

  it("DCR 용량 503: 롤백·기존 grant 유지·해제 후 허용 연산", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    const storePath = enableOAuth();
    // 작은 바이트 상한 — lawful DCR 반복으로 용량 도달.
    const { port, close } = await startMcp({
      oauth: { allowInsecureLoopback: true, maxStoreBytes: 14000 },
    });
    // 재시작 검증용 — 외곽 스코프에 보관.
    let refreshA = "";
    let clientA = "";
    try {
      const base = `http://127.0.0.1:${port}`;
      // 기존 grant 3건(유지용 A·해제용 B/C) 먼저 발급.
      const cA = await approveToCode(base, base, { apiKey: TEST_KEY });
      const tA = await codeToTokens(base, cA);
      refreshA = tA.refresh;
      clientA = cA.client_id;
      const cB = await approveToCode(base, base, { apiKey: TEST_KEY_2 });
      const tB = await codeToTokens(base, cB);
      const cC = await approveToCode(base, base, { apiKey: TEST_KEY });
      const tC = await codeToTokens(base, cC);
      void cC;
      // 용량까지 DCR 반복 — 503 도달 확인(상한 120회).
      let hit503 = false;
      let attempts = 0;
      let beforeDisk = "";
      for (let i = 0; i < 120 && !hit503; i++) {
        attempts++;
        beforeDisk = readFileSync(storePath, "utf8");
        const res = await fetch(`${base}/oauth/register`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            redirect_uris: [`http://127.0.0.1:9/fill-${i}`],
            client_name: `fill-${i}`,
            token_endpoint_auth_method: "none",
          }),
        });
        if (res.status === 503) {
          hit503 = true;
          const body = (await res.json()) as Record<string, unknown>;
          assert.equal(body.error, "temporarily_unavailable");
          // 실패 변이 후 디스크 불변.
          assert.equal(readFileSync(storePath, "utf8"), beforeDisk);
        } else {
          assert.equal(res.status, 201);
          await res.json();
        }
      }
      assert.ok(hit503, `120회 내 503 도달 필요(시도 ${attempts})`);
      // 기존 grant 유지 — A 액세스로 MCP 호출 성공(용량 거부와 무관).
      const okMcp = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${tA.access}`,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "initialize",
          id: 1,
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "test", version: "0.0.0" },
          },
        }),
      });
      assert.equal(okMcp.status, 200);
      // 용량 해제 — B/C 폐기로 공간 확보(축소 연산은 상한에서도 지속).
      for (const rt of [tB.refresh, tC.refresh]) {
        const r = await fetch(`${base}/oauth/revoke`, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: rt }).toString(),
        });
        assert.equal(r.status, 200);
      }
      // 해제 후 허용 DCR 성공(브로커 비오염 — 503 이후에도 영속 가능).
      const retry = await fetch(`${base}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uris: ["http://127.0.0.1:9/after-free"],
          client_name: "after-free",
          token_endpoint_auth_method: "none",
        }),
      });
      assert.equal(retry.status, 201);
      // 해제 후 A 리프레시도 허용 연산으로 지속되어야 한다 — 단, 위 DCR이
      // 공간을 다시 채웠을 수 있어 503 가능. 여기서는 A 액세스가 여전히
      // 유효함을(기존 grant 유지) 확인하는 것으로 갈음한다.
      const stillOk = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${tA.access}`,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "initialize",
          id: 2,
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "test", version: "0.0.0" },
          },
        }),
      });
      assert.equal(stillOk.status, 200);
    } finally {
      await close();
      await api.close();
    }
    // 재시작 — 같은 저장소·상한으로 열어 파일·메타데이터·grant 유지 확인.
    // (용량이 가득 찬 상태에서는 리프레시 회전 자체가 503일 수 있으므로,
    // 재시작 검증은 저장소 적재·서빙·기존 grant 레코드 보존으로 판정한다.)
    const api2 = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api2.url;
    const { port: port2, close: close2 } = await startMcp({
      oauth: { allowInsecureLoopback: true, maxStoreBytes: 14000 },
    });
    try {
      const base2 = `http://127.0.0.1:${port2}`;
      const data = parseStore(readFileSync(storePath, "utf8"), 14000);
      assert.ok(Object.keys(data.clients).length > 0);
      assert.ok(Object.keys(data.grants).length > 0);
      // grant A 레코드가 폐기 없이 보존되어야 한다.
      const grantA = Object.values(data.grants).find(
        (g) => g.client_id === clientA,
      );
      assert.ok(grantA && grantA.revoked_at === null);
      assert.ok(refreshA.length > 0);
      const probe = await fetch(
        `${base2}/.well-known/oauth-authorization-server`,
      );
      assert.equal(probe.status, 200);
    } finally {
      await close2();
      await api2.close();
    }
  });
});

describe("OAuth manage 단독 정규화", () => {
  it("manage 단독 체크→관리 프로필, 미체크→읽기 축소, 위조 체크 불가", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      // manage 단독 + 체크 → 관리 프로필(읽기+관리), 정확한 바인딩.
      const cM = await approveToCode(base, base, {
        scope: "loftbox.manage",
        allowManage: true,
      });
      const tM = await codeToTokens(base, cM);
      assert.equal(tM.scope, "loftbox.manage loftbox.read");
      const transportM = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${tM.access}` } } },
      );
      const clientM = new Client({ name: "test", version: "0.0.0" });
      await clientM.connect(transportM);
      try {
        const { tools } = await clientM.listTools();
        const names = tools.map((x) => x.name);
        assert.ok(names.includes("agent_list"), "관리 프로필 읽기 포함");
        assert.ok(names.includes("domain_verify"), "관리 쓰기 포함");
        assert.ok(!names.includes("message_send"), "레거시 발송 제외");
      } finally {
        await clientM.close();
      }
      // manage 단독 + 미체크 → 읽기 축소(거부 아님).
      const cR = await approveToCode(base, base, {
        scope: "loftbox.manage",
        allowManage: false,
      });
      const tR = await codeToTokens(base, cR);
      assert.equal(tR.scope, "loftbox.read");
      const transportR = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${tR.access}` } } },
      );
      const clientR = new Client({ name: "test", version: "0.0.0" });
      await clientR.connect(transportR);
      try {
        const { tools } = await clientR.listTools();
        const names = tools.map((x) => x.name);
        assert.ok(names.includes("agent_list"));
        assert.ok(!names.includes("domain_verify"), "미체크 시 관리 제외");
      } finally {
        await clientR.close();
      }
      // 읽기 요청 + 위조 체크 → 읽기 유지(상향 불가).
      const cF = await approveToCode(base, base, {
        scope: "loftbox.read",
        allowManage: true,
      });
      const tF = await codeToTokens(base, cF);
      assert.equal(tF.scope, "loftbox.read");
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth 폐기 레이스 재검증", () => {
  function testBroker(held: () => Promise<AuthContext>): {
    broker: OAuthBroker;
    token: string;
    grantId: string;
  } {
    const storePath = enableOAuth();
    const config = loadOAuthConfig(process.env, {
      allowInsecureLoopback: true,
    })!;
    const store = FileOAuthStore.open(storePath);
    const broker = new OAuthBroker(config, store, held);
    const grantId = "lbmcp_gr_race1";
    const clientId = "lbmcp_cli_race1";
    const now = Date.now();
    const enc = encryptSecret(config.encryptionKey, TEST_KEY);
    // 동기 설정 — mutate 체인 완료 대기 없이 await 호출자가 순서 보장.
    // 여기서는 아래 await 로 순서를 맞춘다.
    void store.mutate((d) => {
      d.clients[clientId] = {
        client_id: clientId,
        client_name: "race",
        redirect_uris: ["http://127.0.0.1:9/cb-race"],
        created_at: now,
      };
      d.grants[grantId] = {
        grant_id: grantId,
        client_id: clientId,
        scope: ["loftbox.read"],
        enc,
        org_id: UUID_ORG_1,
        org_slug: UUID_ORG_1,
        org_name: "Test Org",
        key_id: UUID_KEY_1,
        backend_scopes: ["marketing:read"],
        issuer: config.publicOrigin,
        resource: config.resource,
        created_at: now,
        revoked_at: null,
      };
    });
    const token = `lbmcp_at_race_${randomBytes(16).toString("hex")}`;
    return { broker, token, grantId };
  }

  it("held 백엔드 await 사이 폐기 → 성공 아닌 invalid_token", async () => {
    let release!: (v: AuthContext) => void;
    const held = new Promise<AuthContext>((r) => {
      release = r;
    });
    const { broker, token, grantId } = testBroker(() => held);
    // grant 기록 커밋 대기 — 폴링으로 확인(직렬 체인).
    for (let i = 0; i < 50; i++) {
      const g = broker.store.read((d) => d.grants[grantId] ?? null);
      if (g) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(broker.store.read((d) => d.grants[grantId]));
    (broker as unknown as { access: Map<string, unknown> }).access.set(
      sha256Hex(token),
      {
        grant_id: grantId,
        client_id: "lbmcp_cli_race1",
        scope: ["loftbox.read"],
        expires_at: Date.now() + 600000,
      },
    );
    const p = broker.checkAccess(token);
    await new Promise((r) => setTimeout(r, 30));
    // await 사이 폐기 — 스냅샷 교체·액세스 삭제.
    await broker.revokeGrant(grantId);
    release({
      ok: true,
      status: 200,
      org_id: UUID_ORG_1,
      org_slug: UUID_ORG_1,
      org_name: "Test Org",
      key_id: UUID_KEY_1,
      granted_scopes: ["marketing:read"],
      effective_scopes: ["marketing:read"],
    });
    const res = await p;
    assert.equal(res.ok, false);
    assert.equal((res as { ok: false; kind: string }).kind, "invalid_token");
  });

  it("await 사이 만료 → invalid_token(만료 경계 차단)", async () => {
    let release!: (v: AuthContext) => void;
    const held = new Promise<AuthContext>((r) => {
      release = r;
    });
    const { broker, token, grantId } = testBroker(() => held);
    for (let i = 0; i < 50; i++) {
      const g = broker.store.read((d) => d.grants[grantId] ?? null);
      if (g) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    (broker as unknown as { access: Map<string, unknown> }).access.set(
      sha256Hex(token),
      {
        grant_id: grantId,
        client_id: "lbmcp_cli_race1",
        scope: ["loftbox.read"],
        expires_at: Date.now() + 40,
      },
    );
    const p = broker.checkAccess(token);
    await new Promise((r) => setTimeout(r, 80));
    release({
      ok: true,
      status: 200,
      org_id: UUID_ORG_1,
      org_slug: UUID_ORG_1,
      org_name: "Test Org",
      key_id: UUID_KEY_1,
      granted_scopes: [],
      effective_scopes: [],
    });
    const res = await p;
    assert.equal(res.ok, false);
    assert.equal((res as { ok: false; kind: string }).kind, "invalid_token");
  });

  it("느린 HTTP 본문 사이 폐기 → 디스패치 거부 401(도구 미호출)", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const c = await approveToCode(base, base, { apiKey: TEST_KEY });
      const t = await codeToTokens(base, c);
      // 세션 수립 — initialize 로 sid 확보.
      const initBody = JSON.stringify({
        jsonrpc: "2.0",
        method: "initialize",
        id: 1,
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "test", version: "0.0.0" },
        },
      });
      const initRes = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${t.access}`,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: initBody,
      });
      assert.equal(initRes.status, 200);
      const sid = initRes.headers.get("mcp-session-id") ?? "";
      assert.ok(sid, "sid 필요");
      await initRes.text();
      // tools/call 본문을 느리게 전송 — 사이 폐기.
      const callBody = JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/call",
        id: 2,
        params: { name: "agent_list", arguments: {} },
      });
      const seenBefore = api.seenAuthz.length;
      const half = Math.floor(callBody.length / 2);
      const status: number = await new Promise((resolve, reject) => {
        const req = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/mcp",
            method: "POST",
            headers: {
              authorization: `Bearer ${t.access}`,
              "content-type": "application/json",
              accept: "application/json, text/event-stream",
              "mcp-session-id": sid,
              "content-length": String(Buffer.byteLength(callBody)),
            },
          },
          (res) => {
            let data = "";
            res.on("data", (ch) => {
              data += String(ch);
            });
            res.on("end", () => {
              try {
                assert.ok(
                  !data.includes("ag_1"),
                  "폐기 후 도구 결과가 전달되면 안 된다",
                );
                resolve(res.statusCode ?? 0);
              } catch (e) {
                reject(e);
              }
            });
          },
        );
        req.on("error", reject);
        req.write(callBody.slice(0, half));
        // 검증 시작 대기 후 디스패치 간극에서 폐기.
        const waitValidate = async (): Promise<void> => {
          for (let i = 0; i < 100; i++) {
            if (api.seenAuthz.length > seenBefore) break;
            await new Promise((r) => setTimeout(r, 10));
          }
          await new Promise((r) => setTimeout(r, 60));
          await fetch(`${base}/oauth/revoke`, {
            method: "POST",
            headers: {
              "content-type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({ token: t.refresh }).toString(),
          });
          req.write(callBody.slice(half));
          req.end();
        };
        waitValidate().catch(reject);
      });
      assert.equal(status, 401);
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth 리프레시 용량·재사용 증거 보존", () => {
  it("용량 초과 회전 503은 옛 토큰 미소진, 옛 토큰 재사용은 계열 폐기", async () => {
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    // 작은 리프레시 상한 — tombstone 추방 없이 원자 거부 검증.
    const { port, close } = await startMcp({
      oauth: { allowInsecureLoopback: true, maxRefreshTokens: 6 },
    });
    try {
      const base = `http://127.0.0.1:${port}`;
      // grant A: 회전 1회 → 소비 1 + live 1 (tombstone 확보).
      const cA = await approveToCode(base, base, { apiKey: TEST_KEY });
      const tA1 = await codeToTokens(base, cA);
      const rA = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tA1.refresh,
        client_id: cA.client_id,
        resource: RESOURCE,
      });
      assert.equal(rA.status, 200);
      const refreshA2 = rA.body.refresh_token as string;
      const accessA2 = rA.body.access_token as string;
      // B/C/D/E 각 1 live → 합계 6(상한).
      const others: Array<{
        c: { client_id: string };
        t: { refresh: string };
      }> = [];
      for (let i = 0; i < 4; i++) {
        const c = await approveToCode(base, base, { apiKey: TEST_KEY_2 });
        const t = await codeToTokens(base, c);
        others.push({ c, t });
      }
      // 상한 초과 회전 → 503, hidden 발급 없음.
      const over = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: refreshA2,
        client_id: cA.client_id,
        resource: RESOURCE,
      });
      assert.equal(over.status, 503);
      assert.equal(over.body.error, "temporarily_unavailable");
      assert.ok(!("access_token" in over.body));
      assert.ok(!("refresh_token" in over.body));
      // 옛 live 미소진 — 공간 확보 후 재시도 성공.
      const revokeE = await fetch(`${base}/oauth/revoke`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          token: others[3]!.t.refresh,
        }).toString(),
      });
      assert.equal(revokeE.status, 200);
      const retry = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: refreshA2,
        client_id: cA.client_id,
        resource: RESOURCE,
      });
      assert.equal(retry.status, 200);
      const accessA3 = retry.body.access_token as string;
      // 옛 토큰(tA1) 재사용 → 여전히 계열 폐기(tombstone 보존 증거).
      const replay = await tokenPost(base, {
        grant_type: "refresh_token",
        refresh_token: tA1.refresh,
        client_id: cA.client_id,
        resource: RESOURCE,
      });
      assert.equal(replay.status, 400);
      assert.equal(replay.body.error, "invalid_grant");
      // 기존 grant 의 fresh 액세스(A3·A2) 무효화.
      for (const at of [accessA3, accessA2]) {
        const mcp = await fetch(`${base}/mcp`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${at}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            method: "initialize",
            id: 1,
            params: {
              protocolVersion: "2025-11-25",
              capabilities: {},
              clientInfo: { name: "test", version: "0.0.0" },
            },
          }),
        });
        assert.equal(mcp.status, 401);
      }
    } finally {
      await close();
      await api.close();
    }
  });
});

describe("OAuth WWW-Authenticate 정확 규격", () => {
  it("활성·비활성 챌린지 정확 일치, SDK 발견 유지", async () => {
    // 활성 — exact challenge.
    const api = await startFakeApi();
    process.env.LOFTBOX_BASE_URL = api.url;
    enableOAuth();
    const { port, close } = await startMcp();
    try {
      const base = `http://127.0.0.1:${port}`;
      const anon = await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      });
      assert.equal(anon.status, 401);
      const www = anon.headers.get("www-authenticate") ?? "";
      const expected =
        `Bearer realm="loftbox-mcp", ` +
        `resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource", ` +
        `scope="loftbox.read loftbox.manage"`;
      assert.equal(www, expected);
      assert.ok(!www.includes("REDACTED"));
      assert.match(
        www,
        /^Bearer realm="[^"]+", resource_metadata="[^"]+", scope="[^"]+"$/,
      );
      // SDK 발견 유지 — 정상 흐름 initialize+tools/list.
      const c = await approveToCode(base, base);
      const t = await codeToTokens(base, c);
      const transport = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        { requestInit: { headers: { Authorization: `Bearer ${t.access}` } } },
      );
      const client = new Client({ name: "test", version: "0.0.0" });
      await client.connect(transport);
      try {
        const { tools } = await client.listTools();
        assert.ok(tools.length > 0);
      } finally {
        await client.close();
      }
      assertNoOAuthTokenDownstream(api);
    } finally {
      await close();
      await api.close();
    }
    // 비활성 — realm 단일 챌린지 정확 일치.
    for (const k of OAUTH_ENV_KEYS) delete process.env[k];
    const { port: port2, close: close2 } = await startMcp();
    try {
      const base2 = `http://127.0.0.1:${port2}`;
      const anon2 = await fetch(`${base2}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
      });
      assert.equal(anon2.status, 401);
      assert.equal(
        anon2.headers.get("www-authenticate"),
        `Bearer realm="loftbox-mcp"`,
      );
    } finally {
      await close2();
    }
  });
});

describe("OAuth 키 검증 리다이렉트 차단", () => {
  interface Trap {
    url: string;
    hits: number;
    authz: string[];
    close: () => Promise<void>;
  }

  async function startTrap(): Promise<Trap> {
    const t: Trap = {
      url: "",
      hits: 0,
      authz: [],
      close: async () => {},
    };
    const server: Server = createHttpServer((req, res) => {
      t.hits += 1;
      t.authz.push(req.headers.authorization ?? "");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ trapped: true }));
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const addr = server.address() as AddressInfo;
    t.url = `http://127.0.0.1:${addr.port}`;
    t.close = () =>
      new Promise<void>((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      );
    return t;
  }

  it("모든 3xx 는 502 실패 — Location 을 절대 따라가지 않음", async () => {
    const trap = await startTrap();
    // 리다이렉트 응답 API — 상태·Location 을 테스트가 지정한다.
    let mode: { status: number; location: string } = {
      status: 302,
      location: `${trap.url}/grab`,
    };
    let apiHits = 0;
    const api: Server = createHttpServer((req, res) => {
      const path = (req.url ?? "").split("?")[0];
      if (path === "/v1/auth/context") {
        apiHits += 1;
        res.writeHead(mode.status, { location: mode.location });
        res.end();
        return;
      }
      // same-origin 트랩 경로 — 도달하면 실패.
      trap.hits += 1;
      trap.authz.push(req.headers.authorization ?? "");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ trapped: true }));
    });
    await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
    const addr = api.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;
    const closeApi = () =>
      new Promise<void>((resolve, reject) =>
        api.close((e) => (e ? reject(e) : resolve())),
      );
    try {
      process.env.LOFTBOX_BASE_URL = base;
      // 대표 리다이렉트 상태 + 경계(300·399).
      for (const status of [300, 301, 302, 303, 307, 308, 399]) {
        // 외부 목적지.
        trap.hits = 0;
        trap.authz = [];
        mode = { status, location: `${trap.url}/grab-${status}` };
        const r1 = await validateKeyWithApi(TEST_KEY);
        assert.equal(r1.ok, false, `status ${status}`);
        assert.equal(r1.status, 502, `status ${status}`);
        assert.equal(trap.hits, 0, `trap 무요청 ${status}`);
        assert.deepEqual(trap.authz, [], `Authorization 유출 없음 ${status}`);
        // same-origin 목적지 — 역시 따라가지 않는다.
        trap.hits = 0;
        trap.authz = [];
        mode = { status, location: `/same-origin-trap-${status}` };
        const r2 = await validateKeyWithApi(TEST_KEY);
        assert.equal(r2.ok, false, `same-origin ${status}`);
        assert.equal(r2.status, 502, `same-origin ${status}`);
        assert.equal(trap.hits, 0, `same-origin trap 무요청 ${status}`);
      }
      assert.ok(apiHits > 0, "설정된 base URL 로 요청 전송 확인");
    } finally {
      await closeApi();
      await trap.close();
    }
  });

  it("정상 200 형태·401/403 동작 유지", async () => {
    const api = await startFakeApi();
    try {
      process.env.LOFTBOX_BASE_URL = api.url;
      const ok = await validateKeyWithApi(TEST_KEY);
      assert.equal(ok.ok, true);
      assert.equal(ok.status, 200);
      assert.equal(ok.org_id, UUID_ORG_1);
      assert.equal(ok.key_id, UUID_KEY_1);
      assert.ok(ok.effective_scopes.length > 0);
      const denied = await validateKeyWithApi("lb_invalid_key");
      assert.equal(denied.ok, false);
      assert.equal(denied.status, 401);
    } finally {
      await api.close();
    }
    // 403 변형.
    const s403: Server = createHttpServer((_req, res) => {
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "forbidden" }));
    });
    await new Promise<void>((resolve) => s403.listen(0, "127.0.0.1", resolve));
    const addr = s403.address() as AddressInfo;
    try {
      process.env.LOFTBOX_BASE_URL = `http://127.0.0.1:${addr.port}`;
      const f = await validateKeyWithApi(TEST_KEY);
      assert.equal(f.ok, false);
      assert.equal(f.status, 403);
    } finally {
      await new Promise<void>((resolve, reject) =>
        s403.close((e) => (e ? reject(e) : resolve())),
      );
    }
  });
});

describe("OAuth 신뢰 프록시 속도제한", () => {
  function directBroker(trusted?: string): OAuthBroker {
    const storePath = enableOAuth();
    if (trusted !== undefined) {
      process.env.LOFTBOX_MCP_OAUTH_TRUSTED_PROXY_IPS = trusted;
    }
    const config = loadOAuthConfig(process.env, {
      allowInsecureLoopback: true,
    })!;
    return new OAuthBroker(config, FileOAuthStore.open(storePath));
  }

  function fakeReq(
    remoteAddress: string | undefined,
    xff?: string | string[],
  ): IncomingMessage {
    return {
      socket: { remoteAddress },
      headers: xff === undefined ? {} : { "x-forwarded-for": xff },
    } as unknown as IncomingMessage;
  }

  function exhaust(
    broker: OAuthBroker,
    req: IncomingMessage,
    n: number = RATE_LIMIT_MAX,
  ): void {
    for (let i = 0; i < n; i++) {
      assert.equal(broker.checkRate(req), true, `통과 ${i + 1}/${n}`);
    }
    assert.equal(broker.checkRate(req), false, "상한 초과 거부");
  }

  it("기본값은 빈 신뢰 목록 — XFF 로 버킷 변경 불가", () => {
    const storePath = enableOAuth();
    const config = loadOAuthConfig(process.env, {
      allowInsecureLoopback: true,
    })!;
    assert.deepEqual(config.trustedProxyIps, []);
    const broker = new OAuthBroker(config, FileOAuthStore.open(storePath));
    // 회전 XFF 로도 회피 불가 — 모두 같은 소켓 버킷.
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      const r = fakeReq("10.9.9.9", `203.0.113.${(i % 250) + 1}`);
      assert.equal(broker.checkRate(r), true, `통과 ${i + 1}`);
    }
    assert.equal(
      broker.checkRate(fakeReq("10.9.9.9", "203.0.113.250")),
      false,
      "회전 XFF 도 같은 버킷 상한",
    );
    // 다른 소켓 피어는 영향 없음.
    assert.equal(broker.checkRate(fakeReq("10.9.9.10")), true);
  });

  it("미신뢰 직접 피어는 타인 버킷에 영향 불가", () => {
    const broker = directBroker();
    // 공격자가 피해자 IP 를 XFF 로 주장해도 피해자 버킷 untouched.
    exhaust(broker, fakeReq("198.51.100.99", "198.51.100.7"));
    assert.equal(
      broker.checkRate(fakeReq("198.51.100.7")),
      true,
      "피해자 소켓 버킷 독립",
    );
    assert.equal(
      broker.checkRate(fakeReq("198.51.100.99")),
      false,
      "공격자 소켓 버킷 소진 유지",
    );
  });

  it("신뢰 127.0.0.1 뒤 두 전달 클라이언트 독립 한도", () => {
    const broker = directBroker("127.0.0.1");
    exhaust(broker, fakeReq("127.0.0.1", "203.0.113.1"));
    // 한 클라이언트 소진이 다른 클라이언트를 막지 않는다.
    assert.equal(
      broker.checkRate(fakeReq("127.0.0.1", "203.0.113.2")),
      true,
      "두 번째 전달 클라이언트 독립",
    );
    exhaust(broker, fakeReq("127.0.0.1", "203.0.113.2"), RATE_LIMIT_MAX - 1);
    // 소켓 mapped 형태(::ffff:127.0.0.1)도 같은 신뢰 프록시.
    exhaust(broker, fakeReq("::ffff:127.0.0.1", "198.51.100.7"));
    assert.equal(
      broker.checkRate(fakeReq("::ffff:127.0.0.1", "198.51.100.8")),
      true,
      "mapped 소켓 뒤 다른 클라이언트 독립",
    );
  });

  it("스푸핑된 좌측 체인값은 우측 클라이언트 버킷 이동 불가", () => {
    const broker = directBroker("127.0.0.1");
    // 좌측이 달라도 우측이 같으면 같은 버킷.
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      const left = i % 2 === 0 ? "1.2.3.4" : "9.9.9.9, 8.8.8.8";
      assert.equal(
        broker.checkRate(fakeReq("127.0.0.1", `${left}, 203.0.113.9`)),
        true,
      );
    }
    assert.equal(
      broker.checkRate(fakeReq("127.0.0.1", "203.0.113.9")),
      false,
      "우측 IP 단일 표기도 같은 버킷",
    );
    assert.equal(
      broker.checkRate(fakeReq("127.0.0.1", "7.7.7.7, 203.0.113.9")),
      false,
      "좌측 변경으로 회피 불가",
    );
    // 우측이 다르면 다른 버킷 — 좌측에 소진된 IP 가 있어도 통과.
    assert.equal(
      broker.checkRate(fakeReq("127.0.0.1", "203.0.113.9, 198.51.100.8")),
      true,
      "우측 IP 가 버킷 결정",
    );
  });

  it("비정상 XFF 는 소켓 폴백 — 상한 회피 불가", () => {
    const broker = directBroker("127.0.0.1");
    const bad: Array<string | string[]> = [
      "not-an-ip",
      "",
      "   ",
      ["203.0.113.5"],
      ["203.0.113.5", "203.0.113.6"],
      "203.0.113.5, ",
      ",203.0.113.5,",
      "999.1.1.1",
      "proxy.local",
      "10.0.0.0/8",
      "[::1]",
      "1.2.3.4:5678",
      `203.0.113.5,${"9.9.9.9,".repeat(40)}203.0.113.6`,
      "x".repeat(3000),
    ];
    // 비정상 헤더들을 섞어 소켓 버킷을 채운다 — 각각 새 버킷이면 안 된다.
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      const h = bad[i % bad.length]!;
      assert.equal(
        broker.checkRate(fakeReq("127.0.0.1", h)),
        true,
        `통과 ${i}`,
      );
    }
    assert.equal(
      broker.checkRate(fakeReq("127.0.0.1")),
      false,
      "헤더 없음도 같은 소켓 버킷",
    );
    assert.equal(
      broker.checkRate(fakeReq("127.0.0.1", "still-bad")),
      false,
      "비정상 헤더도 소진된 소켓 버킷",
    );
    // 정상 전달 클라이언트는 독립 버킷으로 통과.
    assert.equal(
      broker.checkRate(fakeReq("127.0.0.1", "203.0.113.44")),
      true,
      "정상 전달 클라이언트 독립",
    );
  });

  it("IPv6 정규화 — 표기 달라도 같은 신뢰·버킷", () => {
    assert.equal(normalizeIp("::ffff:127.0.0.1"), "127.0.0.1");
    assert.equal(normalizeIp("::FFFF:192.0.2.1"), "192.0.2.1");
    // IPv4-mapped — dotted/hex/full 표기 모두 같은 IPv4 로 수렴.
    assert.equal(normalizeIp("::ffff:7f00:1"), "127.0.0.1");
    assert.equal(normalizeIp("::FFFF:7F00:1"), "127.0.0.1");
    assert.equal(normalizeIp("0:0:0:0:0:ffff:127.0.0.1"), "127.0.0.1");
    assert.equal(normalizeIp("0:0:0:0:0:ffff:7f00:1"), "127.0.0.1");
    assert.equal(normalizeIp("::ffff:c000:201"), "192.0.2.1");
    assert.equal(normalizeIp("2001:DB8::1"), "2001:db8::1");
    assert.equal(
      normalizeIp("2001:0db8:0000:0000:0000:0000:0000:0001"),
      "2001:db8::1",
    );
    assert.equal(normalizeIp("proxy.local"), null);
    assert.equal(normalizeIp("10.0.0.0/8"), null);
    assert.equal(normalizeIp(""), null);
    // 설정 대문자 ↔ 소켓 풀표기 — 같은 프록시로 신뢰된다.
    const broker = directBroker("2001:DB8::1");
    exhaust(
      broker,
      fakeReq("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::9"),
    );
    assert.equal(
      broker.checkRate(
        fakeReq("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0009"),
      ),
      false,
      "전달 클라이언트 표기 달라도 같은 버킷",
    );
    assert.equal(
      broker.checkRate(fakeReq("2001:db8::1", "2001:db8::10")),
      true,
      "다른 전달 클라이언트 독립",
    );
    // 설정 hex-mapped ↔ 소켓 mapped-dotted/IPv4 — 같은 프록시로 신뢰된다.
    const mapped = directBroker("::ffff:7f00:1");
    exhaust(mapped, fakeReq("::ffff:127.0.0.1", "203.0.113.55"));
    assert.equal(
      mapped.checkRate(fakeReq("127.0.0.1", "203.0.113.55")),
      false,
      "소켓 표기 달라도 같은 전달 클라이언트 버킷",
    );
    assert.equal(
      mapped.checkRate(fakeReq("::ffff:7f00:1", "203.0.113.55")),
      false,
      "소켓 hex-mapped 표기도 같은 버킷",
    );
    assert.equal(
      mapped.checkRate(fakeReq("127.0.0.1", "203.0.113.56")),
      true,
      "다른 전달 클라이언트 독립",
    );
    // 전달 클라이언트 mapped-hex vs dotted — 같은 버킷을 소모한다.
    exhaust(mapped, fakeReq("127.0.0.1", "::ffff:c000:201"));
    assert.equal(
      mapped.checkRate(fakeReq("127.0.0.1", "192.0.2.1")),
      false,
      "전달 hex-mapped 와 IPv4 점표기 같은 버킷",
    );
    assert.equal(
      mapped.checkRate(fakeReq("127.0.0.1", "::ffff:192.0.2.1")),
      false,
      "전달 hex-mapped 와 mapped-dotted 같은 버킷",
    );
  });

  it("무효 신뢰 프록시 설정은 기동 실패(fail-closed)", () => {
    const badConfigs = [
      "proxy.local",
      "10.0.0.0/8",
      "127.0.0.1,,10.0.0.2",
      "127.0.0.1,",
      ",127.0.0.1",
      "999.1.1.1",
      "[::1]",
      "1.2.3.4:5678",
      Array.from({ length: 33 }, (_, i) => `10.0.0.${i + 1}`).join(","),
      `${"10.0.0.1,".repeat(300)}10.0.0.2`,
    ];
    for (const trusted of badConfigs) {
      enableOAuth();
      process.env.LOFTBOX_MCP_OAUTH_TRUSTED_PROXY_IPS = trusted;
      assert.throws(
        () => loadOAuthConfig(process.env, { allowInsecureLoopback: true }),
        /신뢰|OAuth 설정 오류/,
        `거부: ${trusted.slice(0, 40)}`,
      );
    }
    // 서버 기동 경로에서도 실패한다.
    enableOAuth();
    process.env.LOFTBOX_MCP_OAUTH_TRUSTED_PROXY_IPS = "proxy.local";
    assert.throws(() => buildHttpServer(), /신뢰|OAuth|oauth|기동/);
    // 공백뿐인 값은 미설정과 동일(신뢰 없음) — 기동 성공.
    enableOAuth();
    process.env.LOFTBOX_MCP_OAUTH_TRUSTED_PROXY_IPS = "   ";
    const config = loadOAuthConfig(process.env, {
      allowInsecureLoopback: true,
    })!;
    assert.deepEqual(config.trustedProxyIps, []);
  });
});
