# @loftbox/mcp

LoftBox 공식 **MCP(Model Context Protocol) 서버**. AI 에이전트가 LoftBox 이메일
인프라의 **admin 평면**(메일박스·도메인/DNS·메시징·검색·라벨·웹훅·억제·첨부·이벤트)을
표준 MCP 툴로 다룰 수 있게 한다.

차별점: **HITL 승인 게이트 통합** — 발송이 승인 정책에 걸리면 `pending_approval` 로
큐잉되고, `approval_queue_list` / `message_approve` / `message_reject` 툴로 사람이
검토·결정한다.

> **1차 릴리스 범위**: local stdio transport. 원격(streamable HTTP) transport 와
> 공개 레지스트리/Smithery 등재는 후속. routines·workflow marketplace·operator
> timeline 등 확장 admin 평면은 2차.

## 설치 / 실행

```bash
LOFTBOX_API_KEY=lb_live_xxx npx -y @loftbox/mcp
```

### Claude Desktop

`claude_desktop_config.json` 에 추가(`examples/claude_desktop_config.json` 참고):

```json
{
  "mcpServers": {
    "loftbox": {
      "command": "npx",
      "args": ["-y", "@loftbox/mcp"],
      "env": { "LOFTBOX_API_KEY": "lb_live_your_key_here" }
    }
  }
}
```

### Cursor / 기타 MCP 클라이언트

동일하게 command `npx -y @loftbox/mcp`, env `LOFTBOX_API_KEY` 를 등록한다.

## 환경변수

| 변수 | 필수 | 기본 | 설명 |
|---|---|---|---|
| `LOFTBOX_API_KEY` | ✅ | — | LoftBox API 키(Bearer). |
| `LOFTBOX_BASE_URL` | | `https://api.loftbox.net` | API 베이스 URL. |
| `LOFTBOX_TIMEOUT_MS` | | `30000` | 요청 타임아웃(ms). |
| `LOFTBOX_MCP_READ_ONLY` | | (미설정=전체) | `true` 명시 시 read-only 툴만 등록(stdio·HTTP 공통, 서버 설정). |

## 연결 예제 (로컬 체크아웃, ENV 플레이스홀더)

> 실제 키 값을 적지 마세요. 키는 기존 승인된 운영자 절차로 별도 발급합니다.
> 아래 관리 툴은 이 체크아웃의 미게시 코드이므로, 게시된 패키지(`npx -y
> @loftbox/mcp`)가 아닌 로컬 빌드로 실행하세요.

```bash
# 로컬 체크아웃 빌드(최초 1회, 이후 소스 변경 시 재실행)
npm run build

# 읽기 전용 관리 — 감사/조회용 키(예: marketing:read + domain:read 보유 키)
LOFTBOX_API_KEY=${LOFTBOX_API_KEY_READONLY} node dist/index.js

# 발신 설정 관리 — 설정용 키(예: domain:read + domain:manage + marketing:read + marketing:configure)
LOFTBOX_API_KEY=${LOFTBOX_API_KEY_CONFIGURE} node dist/index.js

# 홈페이지 구독 동기화 — 동기화 전용 키(예: marketing:read + marketing:subscriber:manage)
# send scope 은 동기화에 불필요 — 제외하세요.
LOFTBOX_API_KEY=${LOFTBOX_API_KEY_SYNC} node dist/index.js

# 읽기 전용 모드 — 쓰기 툴 미등록(수동 지명 호출도 불가)
LOFTBOX_MCP_READ_ONLY=true LOFTBOX_API_KEY=${LOFTBOX_API_KEY_READONLY} node dist/index.js
```

원격(Streamable HTTP) transport 는 기존 `npm run start:http` 서버를 그대로
사용한다 — 세션별 `Authorization: Bearer ${LOFTBOX_API_KEY}` 헤더로 인증하고,
`LOFTBOX_MCP_READ_ONLY=true` 는 서버 env 로 동일 적용된다. 호스팅된 원격
엔드포인트에 이 관리 툴이 보이는지는 배포 시점에 달렸다(미배포 상태에서는
로컬 실행으로만 확인 가능).

## 툴 (28 + 관리 17)

| 그룹 | 툴 |
|---|---|
| agents | `agent_create` `agent_get` `agent_list` |
| mailboxes | `mailbox_create` `mailbox_list` `inbox_list` `inbox_ack` |
| messages | `message_send` `message_get` `message_list`(q 검색·label·status 필터) |
| labels | `label_add` `label_remove` |
| **HITL** | `approval_queue_list` `message_approve` `message_reject` |
| **HITL 정책** | `approval_policy_list` `approval_policy_create` |
| threads | `thread_list` `thread_messages` |
| domains | `domain_create` `domain_list` `domain_status`(DNS 안내) |
| suppressions | `suppression_list` `suppression_add` `suppression_remove` |
| attachments | `attachment_list` `attachment_url` |
| events | `event_list` |

각 툴은 MCP `annotations`(`readOnlyHint`·`destructiveHint`·`idempotentHint`·
`openWorldHint`)로 부수효과를 알린다. annotations 는 힌트일 뿐 인가가 아니다 —
실제 인가는 백엔드 scope/capability 게이트가 수행한다
([MCP spec 2025-11-25 server/tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)).

> 웹훅 등록(`webhook_create`)은 signing secret 이 1회만 반환되고 MCP 결과/로그
> 어디로도 흘리면 유출 표면이 되므로 1차에서 제외했다. secret 안전 전달 설계 후 후속.

### 관리 툴 (17, org 관리 평면)

> 이 관리 툴 코드는 체크아웃된 소스 상태이며 **아직 배포·게시되지 않았다**.
> 아래 예제는 로컬 실행 기준이다.

| 그룹 | 툴 | 읽기/쓰기 |
|---|---|---|
| auth | `auth_context`(컨텍스트 자기조회) | 읽기 |
| marketing | `marketing_capability`(자격 파생 뷰) | 읽기 |
| keys | `api_key_list`(메타만), `api_key_revoke`(cascade 폐기) | 읽기 / 쓰기(파괴적) |
| domains | `domain_get` `domain_dns_records` `domain_verify`(검증 시도) `domain_remove` | 읽기·읽기 / 쓰기 / 쓰기(파괴적) |
| audiences | `marketing_audience_list` `marketing_audience_get` `marketing_audience_create` | 읽기·읽기 / 쓰기 |
| sender profiles | `marketing_sender_profile_list` `marketing_sender_profile_get` `marketing_sender_profile_create` `marketing_sender_profile_disable`(one-way) | 읽기·읽기 / 쓰기 / 쓰기(파괴적) |
| sync | `newsletter_subscription_get` `newsletter_subscription_sync`(PUT) | 읽기 / 쓰기 |

쓰기(설정/구독 변경) 툴은 `confirmed: true` 리터럴을 요구한다 — 클라이언트
편의 확인이며 보안 인가 대체가 아니다. `domain_verify` 도 검증 시도·audit
상태를 변경하므로 `confirmed: true` 가 필요하다. 키 발급·raw HTTP·
발송/예약/테스트발송 툴은 두지 않는다. `subscribe` 는 원본 consent 증명
필수(합성 금지)이며, `unsubscribe` 는 org 전체 optout(모든 멤버십 원자 해지
+ consent 철회)이다.

## 권한(scope) 주의

다음 툴은 **admin scope API 키**가 필요하다. 키 권한이 부족하면 명확한 403 안내를
반환한다(서버는 죽지 않음):

- `message_approve`, `message_reject`
- `approval_policy_create`
- `suppression_add`, `suppression_remove`

### 관리 툴 필요 scope 행렬

| 툴 | 필요 scope |
|---|---|
| `auth_context` | 인증만(별도 scope 불필요) |
| `marketing_capability`, `marketing_audience_list/get`, `marketing_sender_profile_list/get`, `newsletter_subscription_get` | `marketing:read` |
| `newsletter_subscription_sync` | `marketing:subscriber:manage` |
| `marketing_audience_create`, `marketing_sender_profile_create/disable` | `marketing:configure` |
| `api_key_list`, `api_key_revoke` | `keys:manage`(`revoke` 는 대상의 부모 키도 가능 — 백엔드 판정) |
| `domain_get`, `domain_dns_records` | `domain:read` |
| `domain_verify`, `domain_remove` | `domain:manage` |

403 은 필요한 fine scope 를 지목한다(막연한 admin 권유 없음). 키는 기존 승인된
운영자 절차로 별도 발급한다 — MCP 가 OAuth/토큰 발급 부트스트랩을 제공하지 않는다.

## 보안 주의

- **API 키**는 `LOFTBOX_API_KEY` env 로만 주입한다. 신뢰된 로컬 환경에서 실행할 것.
- **`attachment_url`** 은 단명 서명 URL 을 반환한다 — 공유 금지, 즉시 사용.
- 발송·승인·억제·정책 생성 등 **비가역 작업은 `destructiveHint`** 로 표시된다.

## 개발

```bash
npm install
npm run typecheck && npm run build && npm test
```

MIT License.
