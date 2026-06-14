# loftbox-mcp 설계 (#228 — 공식 MCP 서버, 1차)

## 목표
경쟁사(Mailtrap MCP ~80툴 풀 라이프사이클, AgentMail `npx agentmail-mcp`)에 대응하는 **공식 LoftBox MCP 서버**. 단순 send 가 아니라 **에이전트 admin 평면 전체**(메일박스/도메인/DNS/webhook/승인 큐/delivery 로그)를 MCP 툴로 노출. **차별점 = HITL 승인 게이트 통합**(3사 모두 없음).

## 스코프 결정 (1차 릴리스 = 이 PR)
- **포함**: local stdio transport, **핵심 admin 평면 툴**(메시징·메일박스·도메인·승인·웹훅·억제·첨부·이벤트, 라이브 API 실존 라우트만), HITL 승인 큐·승인 정책 툴, env 기반 설정, CI+publish 워크플로, README(Claude Desktop/Cursor/npx 설정 스니펫).
- **후속 분리**: 원격 streamable HTTP transport(별도), 레지스트리/Smithery/mcp.so 등재(게시 후), `@loftbox/sdk` 의존 전환(SDK npm 게시 후 Phase 2), **2차 admin 평면**(routines·workflow marketplace·operator timeline·key rotate·org export·GDPR delete — 라이브 라우트 존재하나 1차 범위 밖).
- 근거: #228 스코프가 거대 → #259(예약 rate-limit 분리)와 동일하게 1차는 검증가능한 핵심으로 출하. caspar 가 설계 위임("스스로 설계하고"). **"전체"가 아니라 "핵심" admin 평면임을 정직히 표기**(codex 설계리뷰 Major 반영).

## 구현 위치 결정
- **별도 서브모듈 레포 `loftbox-mcp`** (패키지 `@loftbox/mcp`, bin `loftbox-mcp`). 경쟁사 `npx agentmail-mcp` 발견성 패턴.
- **자기완결형(SDK 비의존)**: SDK 가 아직 npm 미게시. 별도 standalone 레포가 `file:../sdk-ts` 에 의존하면 단독 체크아웃 CI/게시가 깨짐(형제 디렉토리 없음). 따라서 MCP 는 SDK 의 검증된 `request()` 의미론(Bearer, AbortController 타임아웃, nested 오류 파싱, Retry-After)을 그대로 가진 **얇은 내부 HTTP 클라이언트** 보유. SDK npm 게시 후 Phase 2 에서 `@loftbox/sdk` 의존으로 전환(후속). 발산 위험은 README/주석에 명시.

## 기술 스택 (버전 고정 — codex Minor 반영)
- `@modelcontextprotocol/sdk` `^1.29` — **고수준 `McpServer`**(`server/mcp.js`) + `StdioServerTransport`(`server/stdio.js`). 고수준 API 가 tools capability 자동 선언(codex C2 해소), zod inputSchema→루트 object JSON Schema 변환(codex zod-루트 해소), `annotations`·`outputSchema`/`structuredContent` 네이티브 지원.
- `zod` `^3.25`(SDK 가 `^3.25 || ^4.0` 허용 — 3.25 안정 채택), `zod-to-json-schema` 불요(SDK 내장 변환 사용).
- TypeScript, ESM(NodeNext), node 18+.
- 테스트: `node --test`(`tsx`) + 주입형 fetch mock(SDK 테스트와 동일 패턴).

## 파일 구조
- `src/api.ts` — `LoftBoxApi` 얇은 클라이언트. `request<T>(method, path, {json, query, headers})` → `{ data, headers, status }`(body 만이 아니라 **응답 헤더도 반환** — codex Major: `Idempotent-Replayed` 캡처 필요). 오류는 `ApiError(status, message, retryAfter?, body?)` throw. SDK 의 검증된 의미론(Bearer, AbortController 타임아웃, nested 오류 파싱, Retry-After) 복제 + 헤더 노출.
- `src/redact.ts` — 민감필드 리댁션(codex C3). webhook `secret` 은 결과에서 마스킹하고 전체값은 **stderr 로 1회 출력**(stdio JSON-RPC 와 분리된 채널 → 모델 컨텍스트·로그 오염 없음, 운영자만 봄). presigned URL 은 기능상 노출 불가피 → 단명 경고 description.
- `src/tools.ts` — 툴 레지스트리. 각 툴 `{ name, title, description, inputSchema: ZodRawShape, annotations: ToolAnnotations, outputShape?, handler(api, args) }`. 핸들러는 `{ structured, text? }` 반환 → 서버가 `content`(text)+`structuredContent` 병행 포장(codex Minor).
- `src/server.ts` — `McpServer` 생성, `registerTool(name, {title, description, inputSchema, annotations, outputSchema}, handler)`. capabilities 자동. 결과 `{ content:[{type:'text',text}], structuredContent, isError }`. ApiError → `isError:true` + 사람이 읽는 메시지(상태코드). **admin scope 403 은 "이 툴은 admin scope API 키 필요" 안내**(codex C1). env 로드(`LOFTBOX_API_KEY` 필수, `LOFTBOX_BASE_URL`·`LOFTBOX_TIMEOUT_MS` 옵션).
- `src/index.ts` — `#!/usr/bin/env node`. **모든 로그·기동 메시지·오류는 stderr 로만**(codex Minor: stdout=JSON-RPC 전용). `main().catch(e=>{ console.error(e); process.exit(1) })`. env 누락 시 stderr 안내 후 exit(1).
- `tests/*.test.ts` — 각 툴 핸들러 mock fetch 로 요청 method/path/query/body/헤더·결과 파싱·오류 매핑 검증 + 레지스트리 무결성(이름 유니크, **모든 inputSchema 가 루트 object JSON Schema 로 변환**, annotations 존재) + 리댁션(secret 마스킹) + replay 헤더 캡처.
- `.github/workflows/{ci,publish}.yml`, `README.md`, `examples/`, `LICENSE`, `tsconfig.json`, `package.json`, `package-lock.json`.

## codex 설계리뷰 반영 요약 (라이브 OpenAPI 교차검증 기준)
**반영(유효)**: C1 admin scope 403 우아한 안내+README scope 표기 / C2 McpServer 로 capabilities 자동 / C3 webhook secret 리댁션(stderr 1회) / Major: `message_send` 결과에 status 분기(`queued|pending_approval|blocked`) 노출 / `Idempotent-Replayed` 헤더 캡처→결과 / "전체"→"핵심" 정직 표기, 2차 평면 분리 / inputSchema 루트 object 강제 / ToolAnnotations(readOnly·destructive·idempotent·openWorld) / structuredContent 병행 / stdout 오염 방지 / 버전 고정.
**무효(codex 가 로컬 stale core 기준 — 라이브 API 와 불일치)**: q/label 미지원(→ **라이브 GET /v1/messages 에 실존**, #236/#238 배포됨) / 누락 엔드포인트(domain verify·dns, webhook list/delete/deliveries → **라이브 미존재**, stale core 에만 있음) / event_list≠delivery(→ 라이브에 deliveries 라우트 없음, `/v1/events` 가 최선).
**부분**: HITL 큐 OutboundApprovalRequest 상세 — 라이브에 별도 조회 라우트 없음 → message(status=pending_approval) 기반 유지, 부가 필드는 message 응답에 있으면 그대로 노출(Extensible).

> **코드리뷰 후 갱신**: webhook_create 는 secret 유출 위험으로 1차 제외 → 총 **28 툴**. structuredContent/outputSchema 는 text-only 로 후퇴(Phase 2). 상세는 맨 아래 "codex 코드리뷰 반영" 참고.

## 툴 목록 (28, 에이전트 admin 평면 — webhook 제외)
| 그룹 | 툴 | 매핑 |
|---|---|---|
| agents | agent_create, agent_get, agent_list | POST/GET /v1/agents |
| mailboxes | mailbox_create, mailbox_list, inbox_list, inbox_ack | /v1/agents/{id}/mailboxes, /v1/mailboxes/{id}/inbox(/ack) |
| messages | message_send, message_get, message_list | /v1/messages (q=검색, label/status/direction 필터, send_at 예약, Idempotency-Key) |
| labels | label_add, label_remove | /v1/messages/{id}/labels |
| **HITL** | approval_queue_list, message_approve, message_reject | message_list(status=pending류) + /approve, /reject |
| **HITL 정책** | approval_policy_list, approval_policy_create | /v1/approval-policies |
| threads | thread_list, thread_messages | /v1/threads |
| domains | domain_create, domain_list, domain_status | /v1/domains (status 의 next_actions=DNS 안내) |
| ~~webhooks~~ | ~~webhook_create~~ | **1차 제외** — signing secret 유출 표면(아래 참고) |
| suppressions | suppression_list, suppression_add, suppression_remove | /v1/suppressions |
| attachments | attachment_list, attachment_url | /v1/messages/{id}/attachments, /v1/attachments/{id}/url |
| events | event_list | /v1/events (delivery 로그) |

## 보안·신뢰성
- API 키는 env(`LOFTBOX_API_KEY`)로만. 절대 로그·툴 결과에 미출력.
- **민감필드 리댁션(codex C3)**: webhook `secret` 은 tool result 에서 마스킹(앞4·뒤4 만), 전체값은 stderr 1회 출력. presigned URL 은 다운로드에 필요해 노출하되 description 에 "단명 서명 URL·공유 금지" 명시.
- **admin scope(codex C1)**: approval_policy_create / message_approve / message_reject / suppression(manual) 등은 서버에서 admin scope API 키 필요. 키 scope 부족 시 API 가 403 → 툴은 "admin scope API 키 필요" 명확 안내(빈 결과·crash 아님). README 에 툴별 scope 요구 표기. (caspar 환경에 admin scope 키 발급 경로 미비 — 운영 제약, [[infra-hermes-loftbox]] 참고.)
- **ToolAnnotations(codex Major)**: 각 툴에 `readOnlyHint`(list/get/status), `destructiveHint`(suppression_remove, reject), `idempotentHint`(label/ack/approve), `openWorldHint:true`(외부 API 호출이므로 전부).
- **message_send 부수효과(codex Major)**: description 에 "실제 발송 트리거. HITL 정책에 따라 결과 status 가 `queued`(즉시 발송 큐)·`pending_approval`(승인 대기)·`blocked`(정책 차단)로 분기" 명시. 결과에 status + (replay 시) `idempotent_replayed:true` 노출.
- 모든 경로 세그먼트 `encodeURIComponent`. query 의 undefined/null 누락.
- 오류: ApiError → `isError:true` + 사람이 읽는 메시지(상태코드 포함). 429 는 retry_after 안내.
- 타임아웃 기본 30s, `LOFTBOX_TIMEOUT_MS` 로 조정.

## 검증
- 단위: 툴별 핸들러 mock fetch — 요청 method/path/query/body/헤더, 결과 파싱, 오류 매핑.
- 레지스트리: 툴 이름 유니크, 모든 inputSchema zod→JSON Schema 변환 성공.
- 스모크: `LOFTBOX_API_KEY` 실키로 stdio 기동 → `tools/list` → `agent_list`/`domain_list` 호출 E2E(라이브). MCP Inspector 또는 간이 클라이언트 스크립트.
- 게이트: codex 설계리뷰 → TDD → codex 코드리뷰 → PR(CodeRabbit+CI).

## codex 코드리뷰 반영 (라이브 기준)
**반영(유효)**: webhook_create 1차 제외(secret 은 result/stderr 어디로도 유출 표면, 라이브 재조회 라우트 없음 → 비노출 불가 → 제거가 정답, redact 모듈도 삭제) / 204·빈본문 → invokeTool 에서 `undefined`→`{ok:true}` 가드 / structuredContent 약속 철회(text-only, Phase 2) / 비가역 툴(message_send·approve·reject·suppression_add/remove·approval_policy_create) `destructiveHint:true` / 403 단정 제거→권한 일반 안내 / timeout(AbortError) 구분 메시지 / 테스트 28툴 전수 매핑+in-process tools-list/capabilities+204 가드+timeout(44개).
**무효/부분**: optional 필드 null 전송 422 위험 — sdk-ts 로 라이브 검증된 패턴(이전 스프린트 #232/#236/#238/#241), 라이브 API 가 null 수용 → 유지.

## 확인된 사실 (core 소스)
- message status 유효값(GET /v1/messages status 필터): `queued|pending_approval|approved|rejected|blocked|sending|sent|failed|delivered|bounced|complained`.
- **HITL 승인 큐 = message_list(status=`pending_approval`, direction=`outgoing`)**. approval_queue_list 툴은 이 필터를 고정.

## 미해결/리스크
- 자기완결형이라 SDK 와 클라이언트 로직 중복 → SDK 게시 후 통합(Phase 2 후속 이슈).
