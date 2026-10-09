/** LoftBox MCP 관리 툴 (org 관리 평면).
 *
 * 기존 `tools.ts` 레지스트리와 같은 `ToolDef` 모양을 쓰되, 이 모듈은
 * org 관리에 필요한 읽기·설정·구독동기 툴만 둔다. 키 발급·raw HTTP·발송/
 * 예약/테스트발송 툴은 의도적으로 두지 않는다(스코프 외).
 *
 * 규칙:
 * - 모든 경로 세그먼트 `encodeURIComponent`, API 입력은 백엔드 입력과 1:1.
 * - 읽기 툴은 `readOnlyHint`, 설정/구독 변경 툴은 `confirmed: literal(true)`
 *   (클라이언트 편의 확인 — 보안 인가 대체 아님. 실제 인가는 백엔드
 *   scope/capability 게이트).
 * - annotations 는 힌트일 뿐 인가가 아니다(MCP spec 2025-11-25 server/tools).
 * - 모델 가시 결과에 평문 자격을 절대 싣지 않는다.
 */

import { z } from "zod";
import type { LoftBoxApi } from "./api.js";
import { ApiError } from "./api.js";
import { DESTRUCTIVE, READ, WRITE } from "./tools.js";
import type { ToolDef } from "./tools.js";

type Args = Record<string, unknown>;

const enc = encodeURIComponent;

/** JSON 안전 최대 정수(2^53-1) — 백엔드 MAX_SAFE_INTEGER 와 동일. */
export const MAX_SAFE_INTEGER = 9007199254740991;

/** 경로/공개 ID 상한. */
const boundedId = (max = 128) => z.string().min(1).max(max);
const emailHash = z.string().regex(/^[0-9a-f]{64}$/, "소문자 sha256 hex 64자");
const safeSlug = z
  .string()
  .regex(/^[a-z0-9][a-z0-9-_]{0,63}$/, "safe slug 1..64(소문자·숫자·-·_)");

/** 변경 툴의 클라이언트 편의 확인 — 리터럴 true 만 허용(인가 대체 아님). */
const confirmed = z
  .literal(true)
  .describe("변경 확인(클라이언트 편의 — 보안 인가 대체 아님). 반드시 true.");

/** 구독 동기화 consent 원본 증명 — 백엔드 ConsentProofInput 과 1:1.
 *  subscribe 에만 필수. 합성 금지: 호출자가 준 원본 그대로 전달한다. */
const consentProof = z.object({
  proof_source: z.string().min(1).max(64),
  version: z.string().min(1).max(64),
  text: z.string().min(1).max(2000),
  collected_at: z
    .string()
    .datetime({ offset: true })
    .describe("원본 수집 시각(RFC3339). 합성·기본값 금지."),
});

/** newsletter sync flat 스냅샷/오류 — 백엔드 `subscriptions.rs` 계약 그대로.
 *  state: absent|subscribed|unsubscribed|blocked (compute_snapshot).
 *  block_reason: hard_bounce|complaint|suppressed|manual (blocked_reason_for).
 *  error: revision_conflict|version_conflict|stale_consent (409),
 *  recipient_blocked (422). */
export interface SyncErrorSnapshot {
  email_hash: string;
  version: number;
  state: string;
  block_reason: string | null;
  last_unsubscribed_at: string | null;
  source_revision: number;
  error: string;
}

const SYNC_STATES = [
  "absent",
  "subscribed",
  "unsubscribed",
  "blocked",
] as const;
const SYNC_BLOCK_REASONS = [
  "hard_bounce",
  "complaint",
  "suppressed",
  "manual",
] as const;
const SYNC_ERRORS_409 = [
  "revision_conflict",
  "version_conflict",
  "stale_consent",
] as const;
const SYNC_ERROR_422 = "recipient_blocked" as const;

/** 409/422 본문 전체 상한 — 초과 시 malformed 취급(무한반사 방지). */
const SYNC_ERROR_BODY_MAX_BYTES = 4096;
const HASH_RE = /^[0-9a-f]{64}$/;
const RFC3339_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})$/;

function isSafeNonNegativeInt(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isInteger(v) &&
    v >= 0 &&
    v <= MAX_SAFE_INTEGER
  );
}

function isBoundedRfc3339(v: unknown): v is string {
  if (typeof v !== "string") return false;
  if (v.length === 0 || v.length > 64) return false;
  if (!RFC3339_RE.test(v)) return false;
  return !Number.isNaN(Date.parse(v));
}

/** 409/422 본문을 bounded flat 스냅샷으로 검증 — 통과분만 7개 키로 반환하고
 *  나머지는 버린다. status 가 주어지면 error ↔ status 적합성도 검사한다.
 *  실패(null) 시 호출자는 원본을 반사하지 말고 고정 안전 진단으로 답해야 한다. */
export function pickSyncErrorBody(
  body: unknown,
  status?: number,
): SyncErrorSnapshot | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  try {
    if (JSON.stringify(body)!.length > SYNC_ERROR_BODY_MAX_BYTES) return null;
  } catch {
    return null;
  }
  const src = body as Record<string, unknown>;
  const { email_hash, version, state, block_reason, last_unsubscribed_at } =
    src;
  const { source_revision, error } = src;
  if (typeof email_hash !== "string" || !HASH_RE.test(email_hash)) return null;
  if (!isSafeNonNegativeInt(version)) return null;
  if (!isSafeNonNegativeInt(source_revision)) return null;
  if (
    typeof state !== "string" ||
    !(SYNC_STATES as readonly string[]).includes(state)
  ) {
    return null;
  }
  if (
    block_reason !== null &&
    (typeof block_reason !== "string" ||
      !(SYNC_BLOCK_REASONS as readonly string[]).includes(block_reason))
  ) {
    return null;
  }
  if (
    last_unsubscribed_at !== null &&
    !isBoundedRfc3339(last_unsubscribed_at)
  ) {
    return null;
  }
  if (typeof error !== "string") return null;
  const known409 = (SYNC_ERRORS_409 as readonly string[]).includes(error);
  if (error !== SYNC_ERROR_422 && !known409) return null;
  if (status === 409 && !known409) return null;
  if (status === 422 && error !== SYNC_ERROR_422) return null;
  return {
    email_hash,
    version,
    state,
    block_reason,
    last_unsubscribed_at,
    source_revision,
    error,
  };
}

/** 검증된 409/422 스냅샷 전달용 — invokeTool 이 isError + structuredContent 로 포장. */
export class SyncConflictError extends Error {
  readonly status: number;
  readonly snapshot: SyncErrorSnapshot;
  constructor(status: number, snapshot: SyncErrorSnapshot) {
    super(
      `newsletter sync ${status} (${snapshot.error}): ${JSON.stringify(snapshot)}`,
    );
    this.name = "SyncConflictError";
    this.status = status;
    this.snapshot = snapshot;
  }
}

/** malformed 409/422 본문용 고정 안전 진단 — 원본 본문·메시지를 반사하지 않는다. */
export function syncMalformedMessage(status: number): string {
  return (
    `newsletter sync ${status}: 서버 오류 본문이 flat 스냅샷 계약과 맞지 않아 ` +
    `상세를 표시하지 않습니다(원본 비반사). 스냅샷을 새로 읽고 revision 으로 재시도하세요.`
  );
}

const OPTOUT_WARNING =
  "Org-wide optout: 이 수신자의 모든 오디언스 멤버십이 원자적으로 구독해지되고 " +
  "부여된 모든 consent 가 철회된다. 버전은 org/email 공유 값이다.";

export const MANAGEMENT_TOOLS: ToolDef[] = [
  // ─── auth context ──────────────────────────────────────────────────
  {
    name: "auth_context",
    title: "인증 컨텍스트 조회",
    description:
      "현재 API 키/세션의 인증 컨텍스트(org id/name/slug, api_key_id, " +
      "granted_scopes vs effective_scopes). 인증 외 별도 scope 불필요. " +
      "민감값(키·토큰·이메일)은 반환하지 않는다.",
    inputSchema: {},
    annotations: READ,
    async handler(api: LoftBoxApi) {
      const { data } = await api.request("GET", "/v1/auth/context");
      return data;
    },
  },

  // ─── marketing capability ──────────────────────────────────────────
  {
    name: "marketing_capability",
    title: "마케팅 capability 조회",
    description:
      "org 마케팅 벌크 발송 자격 파생 뷰(org_id/status/trust_level/" +
      "subscription_status/plan_bulk_enabled/allowed/blockers). " +
      "필요 scope: 'marketing:read'. disabled/suspended/구독 비활성에서도 " +
      "읽힌다. 자격만 답한다 — 발신 준비·배달 상태가 아니다.",
    inputSchema: {},
    annotations: READ,
    requiredScopes: ["marketing:read"],
    async handler(api: LoftBoxApi) {
      const { data } = await api.request("GET", "/v1/marketing/capability");
      return data;
    },
  },

  // ─── api keys (metadata + revoke only) ─────────────────────────────
  {
    name: "api_key_list",
    title: "API 키 목록(메타)",
    description:
      "org API 키 메타 목록(시크릿 제외 — 평문 키는 절대 반환하지 않는다). " +
      "필요 scope: 'keys:manage'.",
    inputSchema: {},
    annotations: READ,
    requiredScopes: ["keys:manage"],
    async handler(api: LoftBoxApi) {
      const { data } = await api.request("GET", "/v1/auth/keys");
      return data;
    },
  },
  {
    name: "api_key_revoke",
    title: "API 키 폐기",
    description:
      "API 키를 cascade 폐기한다(파괴적). 필요 scope: 'keys:manage' — " +
      "단, 대상의 부모 키도 자기 자식을 폐기할 수 있다(백엔드 판정). " +
      "사용 중인 자기 자신은 폐기 불가. confirmed=true 필수.",
    inputSchema: { key_id: boundedId(), confirmed },
    annotations: DESTRUCTIVE,
    requiredScopes: ["keys:manage"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "DELETE",
        `/v1/auth/keys/${enc(String(a.key_id))}`,
      );
      return data;
    },
  },

  // ─── domains ───────────────────────────────────────────────────────
  {
    name: "domain_get",
    title: "도메인 조회",
    description:
      "도메인 단건 조회(UUID 또는 dom_ 공개 ID). 필요 scope: 'domain:read'.",
    inputSchema: { domain_id: boundedId(256) },
    annotations: READ,
    requiredScopes: ["domain:read"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "GET",
        `/v1/domains/${enc(String(a.domain_id))}`,
      );
      return data;
    },
  },
  {
    name: "domain_dns_records",
    title: "도메인 DNS 레코드",
    description: "게시해야 할 DNS 레코드 목록. 필요 scope: 'domain:read'.",
    inputSchema: { domain_id: boundedId(256) },
    annotations: READ,
    requiredScopes: ["domain:read"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "GET",
        `/v1/domains/${enc(String(a.domain_id))}/dns`,
      );
      return data;
    },
  },
  {
    name: "domain_verify",
    title: "도메인 검증",
    description:
      "도메인 DNS 검증을 수행한다(읽기 전용 아님 — 검증 시도·audit 상태 변경 발생). " +
      "필요 scope: 'domain:manage'. confirmed=true 필수(클라이언트 편의 확인).",
    inputSchema: { domain_id: boundedId(256), confirmed },
    annotations: WRITE,
    requiredScopes: ["domain:manage"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "POST",
        `/v1/domains/${enc(String(a.domain_id))}/verify`,
      );
      return data;
    },
  },
  {
    name: "domain_remove",
    title: "도메인 제거",
    description:
      "도메인을 soft-delete 한다(파괴적). 필요 scope: 'domain:manage'. " +
      "confirmed=true 필수.",
    inputSchema: { domain_id: boundedId(256), confirmed },
    annotations: DESTRUCTIVE,
    requiredScopes: ["domain:manage"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "DELETE",
        `/v1/domains/${enc(String(a.domain_id))}`,
      );
      return data;
    },
  },

  // ─── marketing audiences ───────────────────────────────────────────
  {
    name: "marketing_audience_list",
    title: "오디언스 목록",
    description: "마케팅 오디언스 목록. 필요 scope: 'marketing:read'.",
    inputSchema: {},
    annotations: READ,
    requiredScopes: ["marketing:read"],
    async handler(api: LoftBoxApi) {
      const { data } = await api.request("GET", "/v1/marketing/audiences");
      return data;
    },
  },
  {
    name: "marketing_audience_get",
    title: "오디언스 조회",
    description: "오디언스 단건 조회(공개 ID). 필요 scope: 'marketing:read'.",
    inputSchema: { audience_public_id: boundedId() },
    annotations: READ,
    requiredScopes: ["marketing:read"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "GET",
        `/v1/marketing/audiences/${enc(String(a.audience_public_id))}`,
      );
      return data;
    },
  },
  {
    name: "marketing_audience_create",
    title: "오디언스 생성",
    description:
      "마케팅 오디언스를 생성한다. 필요 scope: 'marketing:configure'. " +
      "confirmed=true 필수(클라이언트 편의 확인).",
    inputSchema: {
      name: z.string().min(1).max(120),
      description: z.string().max(2000).optional(),
      confirmed,
    },
    annotations: WRITE,
    requiredScopes: ["marketing:configure"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request("POST", "/v1/marketing/audiences", {
        json: { name: a.name, description: a.description ?? null },
      });
      return data;
    },
  },

  // ─── marketing sender profiles ─────────────────────────────────────
  {
    name: "marketing_sender_profile_list",
    title: "발신 프로필 목록",
    description: "마케팅 발신 프로필 목록. 필요 scope: 'marketing:read'.",
    inputSchema: {},
    annotations: READ,
    requiredScopes: ["marketing:read"],
    async handler(api: LoftBoxApi) {
      const { data } = await api.request(
        "GET",
        "/v1/marketing/sender-profiles",
      );
      return data;
    },
  },
  {
    name: "marketing_sender_profile_get",
    title: "발신 프로필 조회",
    description:
      "발신 프로필 단건 조회(공개 ID). 필요 scope: 'marketing:read'.",
    inputSchema: { sender_profile_public_id: boundedId() },
    annotations: READ,
    requiredScopes: ["marketing:read"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "GET",
        `/v1/marketing/sender-profiles/${enc(String(a.sender_profile_public_id))}`,
      );
      return data;
    },
  },
  {
    name: "marketing_sender_profile_create",
    title: "발신 프로필 생성",
    description:
      "마케팅 발신 프로필을 생성한다(from_address 는 지정 도메인 소속이어야 " +
      "하고 도메인은 marketing-ready 여야 한다 — 백엔드 판정). " +
      "필요 scope: 'marketing:configure'. confirmed=true 필수.",
    inputSchema: {
      domain_public_id: boundedId(),
      from_name: z.string().min(1).max(120),
      from_address: z.string().min(1).max(254),
      reply_to_address: z.string().max(254).optional(),
      confirmed,
    },
    annotations: WRITE,
    requiredScopes: ["marketing:configure"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "POST",
        "/v1/marketing/sender-profiles",
        {
          json: {
            domain_public_id: a.domain_public_id,
            from_name: a.from_name,
            from_address: a.from_address,
            reply_to_address: a.reply_to_address ?? null,
          },
        },
      );
      return data;
    },
  },
  {
    name: "marketing_sender_profile_disable",
    title: "발신 프로필 비활성화",
    description:
      "발신 프로필을 비활성화한다(파괴적 — 재활성 API 없음). " +
      "필요 scope: 'marketing:configure'. confirmed=true 필수.",
    inputSchema: { sender_profile_public_id: boundedId(), confirmed },
    annotations: DESTRUCTIVE,
    requiredScopes: ["marketing:configure"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "POST",
        `/v1/marketing/sender-profiles/${enc(String(a.sender_profile_public_id))}/disable`,
      );
      return data;
    },
  },

  // ─── newsletter subscription sync ──────────────────────────────────
  {
    name: "newsletter_subscription_get",
    title: "구독 스냅샷 조회",
    description:
      "홈페이지 동기화용 flat 구독 스냅샷 조회. 필요 scope: 'marketing:read'. " +
      "version/last_unsubscribed_at 은 org/email 공유 값이다.",
    inputSchema: {
      audience_public_id: boundedId(),
      email_hash: emailHash,
      source: safeSlug,
    },
    annotations: READ,
    requiredScopes: ["marketing:read"],
    async handler(api: LoftBoxApi, a: Args) {
      const { data } = await api.request(
        "GET",
        `/v1/marketing/audiences/${enc(String(a.audience_public_id))}` +
          `/subscriptions/${enc(String(a.email_hash))}`,
        { query: { source: a.source as string } },
      );
      return data;
    },
  },
  {
    name: "newsletter_subscription_sync",
    title: "구독 동기화",
    description:
      "홈페이지↔LoftBox 구독 상태 동기화(PUT). 필요 scope: " +
      "'marketing:subscriber:manage'. subscribe 는 원본 consent 증명 필수 " +
      "(합성·기본 now() 금지 — 로그인 사실로 뉴스레터 등록을 인가하지 않는다). " +
      "unsubscribe 는 consent 없이 가능하고 org 전체 optout 이다: " +
      "이 수신자의 모든 오디언스 멤버십이 원자적으로 해지되고 부여된 모든 " +
      "consent 가 철회된다. 409(revision_conflict|version_conflict|stale_consent)·" +
      "422(recipient_blocked)는 flat 스냅샷+error 로 isError 반환. " +
      "confirmed=true 필수.",
    inputSchema: {
      audience_public_id: boundedId(),
      email_hash: emailHash,
      email: z.string().min(1).max(254),
      source: safeSlug,
      source_revision: z.number().int().min(1).max(MAX_SAFE_INTEGER),
      expected_version: z.number().int().min(0).max(MAX_SAFE_INTEGER),
      action: z.enum(["subscribe", "unsubscribe"]),
      consent: consentProof.optional(),
      confirmed,
    },
    annotations: WRITE,
    requiredScopes: ["marketing:subscriber:manage"],
    async handler(api: LoftBoxApi, a: Args) {
      const action = String(a.action);
      if (action === "subscribe" && a.consent == null) {
        throw new Error(
          "subscribe 에는 원본 consent 증명(proof_source/version/text/collected_at)이 필수입니다. 합성하지 마세요.",
        );
      }
      const json: Record<string, unknown> = {
        email: a.email,
        source: a.source,
        source_revision: a.source_revision,
        expected_version: a.expected_version,
        action,
      };
      // unsubscribe 에는 consent 를 싣지 않는다(백엔드도 무시).
      if (action === "subscribe") json.consent = a.consent;
      try {
        const { data } = await api.request(
          "PUT",
          `/v1/marketing/audiences/${enc(String(a.audience_public_id))}` +
            `/subscriptions/${enc(String(a.email_hash))}`,
          { json },
        );
        if (action === "unsubscribe") {
          return {
            ...(data as Record<string, unknown>),
            optout_warning: OPTOUT_WARNING,
          };
        }
        return data;
      } catch (e) {
        if (e instanceof ApiError && (e.status === 409 || e.status === 422)) {
          const flat = pickSyncErrorBody(e.body, e.status);
          if (flat) {
            throw new SyncConflictError(e.status, flat);
          }
          // malformed 409/422: 원본 ApiError(무제한 메시지 반사)를 그대로
          // 던지지 않고 고정 안전 진단으로 답한다.
          throw new Error(syncMalformedMessage(e.status));
        }
        throw e;
      }
    },
  },
];
