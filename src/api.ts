/** LoftBox REST 얇은 클라이언트 (fetch 기반, 의존성 없음).
 *
 * sdk-ts 의 검증된 request() 의미론(Bearer, AbortController 타임아웃,
 * nested 오류 파싱, Retry-After)을 복제하되, MCP 가 필요로 하는 응답 헤더
 * (예: `Idempotent-Replayed`)까지 노출한다 — codex 설계리뷰 Major 반영.
 *
 * SDK npm 게시 후 Phase 2 에서 `@loftbox/sdk` 의존으로 전환 예정(후속).
 */

export const DEFAULT_BASE_URL = "https://api.loftbox.net";
export const DEFAULT_TIMEOUT_MS = 30_000;
export const USER_AGENT = "loftbox-mcp/0.1.0";

export type Query = Record<
  string,
  string | number | boolean | undefined | null
>;

/** API 오류 — 상태코드와 사람이 읽는 메시지, 선택적 retry_after 를 보존. */
export class ApiError extends Error {
  readonly status: number;
  readonly retryAfterSecs?: number;
  readonly body?: unknown;

  constructor(
    status: number,
    message: string,
    opts: { retryAfterSecs?: number; body?: unknown } = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.retryAfterSecs = opts.retryAfterSecs;
    this.body = opts.body;
  }

  /** admin scope 부족 등 권한 거부 여부. */
  get isForbidden(): boolean {
    return this.status === 403;
  }
}

export interface ApiResponse<T> {
  data: T;
  status: number;
  headers: Headers;
}

export interface LoftBoxApiConfig {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  /** 테스트/프록시용 커스텀 fetch. 기본 globalThis.fetch. */
  fetch?: typeof fetch;
}

export interface RequestOptions {
  json?: unknown;
  query?: Query;
  headers?: Record<string, string>;
}

export class LoftBoxApi {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(config: LoftBoxApiConfig) {
    if (!config?.apiKey) throw new Error("apiKey 는 필수입니다");
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const f = config.fetch ?? globalThis.fetch;
    if (!f) {
      throw new Error(
        "fetch 를 사용할 수 없습니다 (Node 18+ 또는 config.fetch 제공)",
      );
    }
    this.fetchImpl = f;
  }

  async request<T = unknown>(
    method: string,
    path: string,
    opts: RequestOptions = {},
  ): Promise<ApiResponse<T>> {
    const url = new URL(this.baseUrl + path);
    if (opts.query) {
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      Accept: "application/json",
      "User-Agent": USER_AGENT,
      ...opts.headers,
    };
    if (opts.json !== undefined) headers["Content-Type"] = "application/json";

    // 타임아웃은 fetch + 본문 읽기 전체를 덮는다(sdk-ts codex 리뷰 Major 동일 보존).
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let resp: Response;
    let text: string;
    try {
      resp = await this.fetchImpl(url.toString(), {
        method,
        headers,
        body: opts.json !== undefined ? JSON.stringify(opts.json) : undefined,
        signal: controller.signal,
      });
      text = await resp.text();
    } catch (e) {
      // AbortError = 타임아웃(우리가 abort 한 경우). 구분해 안내(codex Minor).
      if ((e as Error)?.name === "AbortError") {
        throw new ApiError(0, `요청 타임아웃 (${this.timeoutMs}ms 초과)`);
      }
      throw new ApiError(0, `요청 실패: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }

    let body: unknown = undefined;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
    }

    if (!resp.ok) {
      let message = `HTTP ${resp.status}`;
      let retryAfterSecs: number | undefined;
      if (body && typeof body === "object") {
        const b = body as Record<string, unknown>;
        const err = b.error;
        if (err && typeof err === "object") {
          const eo = err as Record<string, unknown>;
          if (typeof eo.message === "string") message = eo.message;
          if (typeof eo.retry_after === "number")
            retryAfterSecs = eo.retry_after;
        } else if (typeof b.message === "string") {
          message = b.message;
        } else if (typeof err === "string") {
          message = err;
        } else if (typeof b.detail === "string") {
          message = b.detail;
        }
      } else if (typeof body === "string" && body) {
        message = body;
      }
      const headerRa = resp.headers.get("retry-after");
      if (headerRa && /^\d+$/.test(headerRa)) retryAfterSecs = Number(headerRa);
      throw new ApiError(resp.status, message, { retryAfterSecs, body });
    }

    return { data: body as T, status: resp.status, headers: resp.headers };
  }
}
