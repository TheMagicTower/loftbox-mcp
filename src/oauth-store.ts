/** OAuth durable 저장소 — Node18 fs 원시 API만 사용.
 *
 * - 파일 JSON 단일 문서, 원자적 저장(배타적 임시파일+fsync+rename), 파일
 *   mode 0600, 전용 비공개 디렉터리. 쓰기 직렬화(단일 프로세스 전제).
 * - LoftBox API 키는 AES-256-GCM 으로 암호화해서만 보관한다.
 *   평문 키·raw OAuth 토큰을 파일에 절대 쓰지 않는다.
 * - 토큰/코드는 SHA-256 해시로만 인덱싱한다.
 * - 모든 변경은 스냅샷 복사본 위에서 수행하고, persist 성공 후에만
 *   메모리를 교체한다. 콜백/persist 실패 시 부분 변경이 남지 않는다.
 * - grant/리프레시는 발급 시점의 정확한 issuer·resource 에 바인딩된다.
 *   설정 origin 이 바뀐 뒤 옛 저장소를 열어도 다른 audience 로 토큰을
 *   만들지 않는다(토큰 audience 교체 방지).
 * - 만료·폐기·고아 정리(pruning)와 레코드 수 상한을 적용한다. 회전된
 *   리프레시 tombstone 은 원래 만료까지 유지해 재사용을 감지한다.
 *
 * 단일 프로세스만 지원한다: 다중 프로세스가 같은 파일을 쓰면
 * last-write-wins 로 유실될 수 있다(DEPLOY.md 참고).
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import {
  closeSync,
  chmodSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { MAX_CLIENTS, MAX_GRANTS, MAX_REFRESH_TOKENS } from "./oauth-config.js";

export const STORE_VERSION = 1;

/** 저장소 파일 적재 상한(메모리 DoS 백스톱). */
export const MAX_STORE_BYTES = 32 * 1024 * 1024;

/** 용량 초과 거부 — 디스크·메모리 변경 없이 롤백된다. 호출자는
 *  안전 503(temporarily_unavailable)으로 응답하고, 영속 실패(500/503)와
 *  구분한다. 미인증 DCR 용량 거부가 건강한 브로커를 오염시키지 않는다. */
export class StoreCapacityError extends Error {
  constructor(message = "OAuth 저장소 용량 초과") {
    super(message);
    this.name = "StoreCapacityError";
  }
}

export function isStoreCapacityError(e: unknown): e is StoreCapacityError {
  return e instanceof StoreCapacityError;
}
/** 적재 시 레코드 수 하드 상한(런타임 상한의 여유 배수). */
const LOAD_MAX_CLIENTS = MAX_CLIENTS * 4;
const LOAD_MAX_GRANTS = MAX_GRANTS * 4;
const LOAD_MAX_REFRESH = MAX_REFRESH_TOKENS * 4;
/** 폐기된 grant 의 암호화 비밀을 정리하기 전 유예(재시작·감사 여유). */
const REVOKED_GRANT_GRACE_MS = 60 * 60 * 1000; // 1시간
/** 기본 리프레시 TTL(고아 grant 정리 기준, 설정값으로 대체됨). */
const DEFAULT_REFRESH_TTL_MS = 30 * 24 * 3600 * 1000; // 30일

/** DCR 로 등록된 공개 클라이언트(표시 이름은 미검증·출력 시 이스케이프). */
export interface StoredClient {
  client_id: string;
  client_name: string | null;
  redirect_uris: string[];
  created_at: number; // epoch ms
}

/** 사용자 승인 grant — 암호화된 원본 API 키 + 조직 바인딩. */
export interface StoredGrant {
  grant_id: string;
  client_id: string;
  /** 승인된 scope (부분집합, 정렬). */
  scope: string[];
  /** 암호화된 원본 LoftBox API 키(base64 필드). */
  enc: { iv: string; data: string; tag: string };
  /** 승인 시점 auth/context 바인딩(키 교체·org 변경 감지용). */
  org_id: string | null;
  org_slug: string | null;
  org_name: string | null;
  key_id: string | null;
  /** 승인 시 유효 backend scope(참고용 — 인가는 매 요청 재검증). */
  backend_scopes: string[];
  /** 발급 시점의 정확한 issuer(origin)·resource — audience 바인딩. */
  issuer: string;
  resource: string;
  created_at: number;
  revoked_at: number | null;
}

export interface StoredRefresh {
  /** grant 소유권. */
  grant_id: string;
  client_id: string;
  scope: string[];
  /** 발급 시점의 정확한 issuer(origin)·resource — audience 바인딩. */
  issuer: string;
  resource: string;
  created_at: number;
  expires_at: number;
  /** 회전으로 소비된 시각(null=유효). 재사용 감지용으로 보관. */
  consumed_at: number | null;
}

export interface StoreData {
  version: number;
  clients: Record<string, StoredClient>;
  grants: Record<string, StoredGrant>;
  /** key = sha256(refresh token). */
  refresh: Record<string, StoredRefresh>;
}

export function emptyStore(): StoreData {
  return { version: STORE_VERSION, clients: {}, grants: {}, refresh: {} };
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** AES-256-GCM 암호화. key 는 32바이트. */
export function encryptSecret(
  key: Buffer,
  plaintext: string,
): { iv: string; data: string; tag: string } {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return {
    iv: iv.toString("base64"),
    data: data.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

/** 복호화 실패 시 null(호출자는 grant 무효로 처리, 비밀 미노출). */
export function decryptSecret(
  key: Buffer,
  enc: { iv: string; data: string; tag: string },
): string | null {
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(enc.iv, "base64"),
    );
    decipher.setAuthTag(Buffer.from(enc.tag, "base64"));
    const out = Buffer.concat([
      decipher.update(Buffer.from(enc.data, "base64")),
      decipher.final(),
    ]);
    return out.toString("utf8");
  } catch {
    return null;
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function isBoundedString(v: unknown, max: number): v is string {
  return typeof v === "string" && v.length <= max;
}

function isOptBoundedString(v: unknown, max: number): v is string | null {
  return v === null || isBoundedString(v, max);
}

function isEpochMs(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isFinite(v) &&
    v >= 0 &&
    v <= 9007199254740991
  );
}

function isStringArray(
  v: unknown,
  maxItems: number,
  maxLen: number,
): v is string[] {
  return (
    Array.isArray(v) &&
    v.length <= maxItems &&
    v.every((s) => isBoundedString(s, maxLen))
  );
}

/** 저장소 파일 파싱+형태 검증. 손상·초과 시 throw(fail-closed).
 *  구버전 레코드의 issuer/resource 누락은 빈 문자열로 채운다 —
 *  런타임 바인딩 검사가 설정값과 다름을 보고 사용을 거부한다. */
export function parseStore(raw: string, maxBytes = MAX_STORE_BYTES): StoreData {
  if (Buffer.byteLength(raw, "utf8") > maxBytes) {
    throw new Error("OAuth 저장소 크기 초과");
  }
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    throw new Error("OAuth 저장소 파싱 실패(손상됨)");
  }
  if (!isRecord(doc) || doc.version !== STORE_VERSION) {
    throw new Error("OAuth 저장소 버전 불일치");
  }
  if (
    !isRecord(doc.clients) ||
    !isRecord(doc.grants) ||
    !isRecord(doc.refresh)
  ) {
    throw new Error("OAuth 저장소 형태 불일치");
  }
  const clients = doc.clients as Record<string, unknown>;
  const grants = doc.grants as Record<string, unknown>;
  const refresh = doc.refresh as Record<string, unknown>;
  if (
    Object.keys(clients).length > LOAD_MAX_CLIENTS ||
    Object.keys(grants).length > LOAD_MAX_GRANTS ||
    Object.keys(refresh).length > LOAD_MAX_REFRESH
  ) {
    throw new Error("OAuth 저장소 레코드 수 초과");
  }
  for (const [id, c] of Object.entries(clients)) {
    if (
      !isRecord(c) ||
      c.client_id !== id ||
      !isBoundedString(c.client_id, 256) ||
      !isOptBoundedString(c.client_name, 512) ||
      !isStringArray(c.redirect_uris, 32, 2048) ||
      !isEpochMs(c.created_at)
    ) {
      throw new Error("OAuth 저장소 client 레코드 손상");
    }
  }
  for (const [id, g] of Object.entries(grants)) {
    if (
      !isRecord(g) ||
      g.grant_id !== id ||
      !isBoundedString(g.grant_id, 256) ||
      !isBoundedString(g.client_id, 256) ||
      !isStringArray(g.scope, 16, 64) ||
      !isRecord(g.enc) ||
      !isBoundedString(g.enc.iv, 8192) ||
      !isBoundedString(g.enc.data, 8192) ||
      !isBoundedString(g.enc.tag, 8192) ||
      !isOptBoundedString(g.org_id, 512) ||
      !isOptBoundedString(g.org_slug, 512) ||
      !isOptBoundedString(g.org_name, 512) ||
      !isOptBoundedString(g.key_id, 512) ||
      !isStringArray(g.backend_scopes, 256, 256) ||
      (g.issuer !== undefined && !isBoundedString(g.issuer, 2048)) ||
      (g.resource !== undefined && !isBoundedString(g.resource, 2048)) ||
      !isEpochMs(g.created_at) ||
      (g.revoked_at !== null && !isEpochMs(g.revoked_at))
    ) {
      throw new Error("OAuth 저장소 grant 레코드 손상");
    }
    if (g.issuer === undefined) g.issuer = "";
    if (g.resource === undefined) g.resource = "";
  }
  for (const r of Object.values(refresh)) {
    if (
      !isRecord(r) ||
      !isBoundedString(r.grant_id, 256) ||
      !isBoundedString(r.client_id, 256) ||
      !isStringArray(r.scope, 16, 64) ||
      (r.issuer !== undefined && !isBoundedString(r.issuer, 2048)) ||
      (r.resource !== undefined && !isBoundedString(r.resource, 2048)) ||
      !isEpochMs(r.created_at) ||
      !isEpochMs(r.expires_at) ||
      (r.consumed_at !== null && !isEpochMs(r.consumed_at))
    ) {
      throw new Error("OAuth 저장소 refresh 레코드 손상");
    }
    if (r.issuer === undefined) r.issuer = "";
    if (r.resource === undefined) r.resource = "";
  }
  return doc as unknown as StoreData;
}

function euidMatches(stUid: number): boolean {
  return typeof process.getuid !== "function" || stUid === process.getuid();
}

/** 전용 비공개 디렉터리 보장. 기존 디렉터리가 공유/타인 소유/심볼릭
 *  링크면 chmod 로 고치지 않고 거부한다(fail-closed). 상위 공유
 *  디렉터리(/tmp 등)는 검사하지 않는다 — 직속 부모만 검사한다. */
function ensurePrivateDir(dir: string): void {
  let st;
  try {
    st = lstatSync(dir);
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code !== "ENOENT") throw e;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    st = lstatSync(dir);
  }
  if (!st.isDirectory() || st.isSymbolicLink()) {
    throw new Error("OAuth 저장소 부모 경로가 디렉터리가 아닙니다");
  }
  if ((st.mode & 0o077) !== 0) {
    throw new Error(
      "OAuth 저장소 디렉터리 권한이 안전하지 않습니다(0700 전용 필요)",
    );
  }
  if (!euidMatches(st.uid)) {
    throw new Error("OAuth 저장소 디렉터리 소유자가 일치하지 않습니다");
  }
}

/** 저장소 파일 자체 검사 — 심볼릭 링크·비정규 파일을 거부한다. */
function assertStoreFileSafe(path: string): void {
  let st;
  try {
    st = lstatSync(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code === "ENOENT") return;
    throw e;
  }
  if (!st.isFile() || st.isSymbolicLink()) {
    throw new Error("OAuth 저장소 경로가 안전하지 않습니다(심볼릭 링크 금지)");
  }
  if (!euidMatches(st.uid)) {
    throw new Error("OAuth 저장소 파일 소유자가 일치하지 않습니다");
  }
}

/** 원자적 저장: 배타적 임시파일(O_EXCL)+fsync 후 rename, 부모 fsync. */
function atomicWriteFile(path: string, content: string): void {
  const dir = dirname(path);
  ensurePrivateDir(dir);
  assertStoreFileSafe(path);
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(8).toString("hex")}`;
  let fd: number;
  try {
    fd = openSync(tmp, "wx", 0o600);
  } catch (e) {
    throw new Error(
      `OAuth 저장소 임시파일 생성 실패: ${(e as Error)?.message ?? String(e)}`,
    );
  }
  try {
    writeFileSync(fd, content, "utf8");
    fsyncSync(fd);
  } catch (e) {
    try {
      closeSync(fd);
    } catch {
      // 무시.
    }
    try {
      unlinkSync(tmp);
    } catch {
      // 무시.
    }
    throw e;
  }
  closeSync(fd);
  renameSync(tmp, path);
  // 디렉터리 항목의 내구성 — rename 후 부모를 fsync 한다.
  const dfd = openSync(dir, "r");
  try {
    fsyncSync(dfd);
  } finally {
    closeSync(dfd);
  }
}

export interface StoreOpenOptions {
  /** 리프레시 TTL(ms) — 고아 grant 정리 기준. 기본 30일. */
  refreshTtlMs?: number;
  /** 테스트 전용 상한 오버라이드 — 운영 기본은 모듈 상수. */
  maxStoreBytes?: number;
  maxClients?: number;
  maxGrants?: number;
  maxRefreshTokens?: number;
}

export class FileOAuthStore {
  private data: StoreData;
  private chain: Promise<void> = Promise.resolve();
  private readonly refreshTtlMs: number;
  private readonly maxStoreBytes: number;
  private readonly maxClients: number;
  private readonly maxGrants: number;
  private readonly maxRefreshTokens: number;
  readonly path: string;

  private constructor(
    path: string,
    data: StoreData,
    opts: {
      refreshTtlMs: number;
      maxStoreBytes: number;
      maxClients: number;
      maxGrants: number;
      maxRefreshTokens: number;
    },
  ) {
    this.path = path;
    this.data = data;
    this.refreshTtlMs = opts.refreshTtlMs;
    this.maxStoreBytes = opts.maxStoreBytes;
    this.maxClients = opts.maxClients;
    this.maxGrants = opts.maxGrants;
    this.maxRefreshTokens = opts.maxRefreshTokens;
  }

  static open(path: string, opts: StoreOpenOptions = {}): FileOAuthStore {
    const maxStoreBytes = opts.maxStoreBytes ?? MAX_STORE_BYTES;
    // 심볼릭 링크 저장소는 읽기 전에 거부한다.
    assertStoreFileSafe(path);
    let data: StoreData;
    try {
      const st = statSync(path);
      if (!st.isFile()) {
        throw new Error("OAuth 저장소 경로가 파일이 아닙니다");
      }
      if (st.size > maxStoreBytes) {
        throw new Error("OAuth 저장소 크기 초과");
      }
      data = parseStore(readFileSync(path, "utf8"), maxStoreBytes);
    } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code === "ENOENT") {
        data = emptyStore();
      } else {
        throw e;
      }
    }
    const store = new FileOAuthStore(path, data, {
      refreshTtlMs: opts.refreshTtlMs ?? DEFAULT_REFRESH_TTL_MS,
      maxStoreBytes,
      maxClients: opts.maxClients ?? MAX_CLIENTS,
      maxGrants: opts.maxGrants ?? MAX_GRANTS,
      maxRefreshTokens: opts.maxRefreshTokens ?? MAX_REFRESH_TOKENS,
    });
    // 신규 파일이면 즉시 생성해 권한 문제를 기동 시점에 드러낸다.
    store.persist(store.data);
    try {
      chmodSync(path, 0o600);
    } catch {
      // 무시.
    }
    return store;
  }

  /** 쓰기 뮤텍스 — 모든 변경은 스냅샷 복사본 위에서 수행하고,
   *  persist 성공 후에만 메모리를 교체한다. 콜백 예외·persist 실패·용량
   *  초과 시 메모리에 부분 변경이 남지 않는다(롤백). 용량 초과는
   *  StoreCapacityError 로 구분되며 디스크 쓰기 없이 거부된다. */
  mutate<T>(fn: (data: StoreData) => T): Promise<T> {
    const run = this.chain.then(() => {
      const beforeJson = JSON.stringify(this.data);
      const beforeClients = Object.keys(this.data.clients).length;
      const beforeGrants = Object.keys(this.data.grants).length;
      const beforeRefresh = Object.keys(this.data.refresh).length;
      const draft: StoreData = JSON.parse(beforeJson) as StoreData;
      const result = fn(draft);
      this.pruneLocked(draft, Date.now());
      this.checkCapacityLocked(draft, {
        beforeClients,
        beforeGrants,
        beforeRefresh,
      });
      this.persist(draft);
      this.data = draft;
      return result;
    });
    // 체인이 끊기지 않게 실패를 삼킨 후속 체인을 유지한다.
    // 용량 거부 후에도 다음 허용 연산은 정상 수행된다(브로커 비오염).
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /** 읽기 — 호출자는 반환값을 변경하지 않는다. */
  read<T>(fn: (data: StoreData) => T): T {
    return fn(this.data);
  }

  private persist(draft: StoreData): void {
    // 디스크 쓰기·메모리 커밋 전에 직렬화 UTF-8 바이트 상한을 검사한다.
    // 초과분은 파일을 키우지 않고 거부 — 재시작 불가 파일을 만들지 않는다.
    const serialized = JSON.stringify(draft);
    if (Buffer.byteLength(serialized, "utf8") > this.maxStoreBytes) {
      throw new StoreCapacityError("OAuth 저장소 직렬화 크기 초과");
    }
    atomicWriteFile(this.path, serialized);
  }

  /** 안전 정리만 수행한다(만료·폐기·고아) — mutate 트랜잭션 안에서만 호출.
   *  회전된 리프레시 tombstone(consumed, 미만료, grant 유효)은
   *  재사용 감지를 위해 원래 만료까지 유지한다. 유효(active) 레코드는
   *  상한 이유로 절대 추방하지 않는다 — 초과 성장은 checkCapacityLocked 가
   *  원자적으로 거부한다(StoreCapacityError, 롤백). */
  private pruneLocked(d: StoreData, now: number): void {
    // 만료·grant 상실·grant 폐기된 리프레시 제거.
    for (const [h, r] of Object.entries(d.refresh)) {
      const g = d.grants[r.grant_id];
      if (!g || g.revoked_at !== null || r.expires_at <= now) {
        delete d.refresh[h];
      }
    }
    // 폐기 grant: 유예 후 암호화 비밀 정리(살아있는 리프레시가 없을 때).
    for (const gid of Object.keys(d.grants)) {
      const g = d.grants[gid]!;
      if (g.revoked_at === null) continue;
      if (now - g.revoked_at <= REVOKED_GRANT_GRACE_MS) continue;
      let live = false;
      for (const r of Object.values(d.refresh)) {
        if (r.grant_id === gid) {
          live = true;
          break;
        }
      }
      if (!live) delete d.grants[gid];
    }
    // 고아 grant: 어떤 리프레시도 없고 TTL+유예가 지났으면 정리.
    // (grant 생성 직후 코드 교환 전 수 분은 해당 없음 — TTL 기준이 길다.)
    for (const gid of Object.keys(d.grants)) {
      const g = d.grants[gid]!;
      if (g.revoked_at !== null) continue;
      if (now - g.created_at <= this.refreshTtlMs + REVOKED_GRANT_GRACE_MS) {
        continue;
      }
      let referenced = false;
      for (const r of Object.values(d.refresh)) {
        if (r.grant_id === gid) {
          referenced = true;
          break;
        }
      }
      if (!referenced) delete d.grants[gid];
    }
  }

  /** 상한 초과 성장을 원자적으로 거부한다. 축소·동일(폐기·만료 정리 등)은
   *  초과 파일 정리 경로를 막지 않게 허용한다. */
  private checkCapacityLocked(
    d: StoreData,
    before: {
      beforeClients: number;
      beforeGrants: number;
      beforeRefresh: number;
    },
  ): void {
    const afterClients = Object.keys(d.clients).length;
    const afterGrants = Object.keys(d.grants).length;
    const afterRefresh = Object.keys(d.refresh).length;
    if (
      (afterClients > this.maxClients && afterClients > before.beforeClients) ||
      (afterGrants > this.maxGrants && afterGrants > before.beforeGrants) ||
      (afterRefresh > this.maxRefreshTokens &&
        afterRefresh > before.beforeRefresh)
    ) {
      throw new StoreCapacityError("OAuth 저장소 레코드 상한 초과");
    }
  }
}
