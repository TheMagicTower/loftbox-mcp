# @loftbox/mcp

LoftBox 공식 **MCP(Model Context Protocol) 서버**. AI 에이전트가 LoftBox 이메일
인프라의 **admin 평면**(메일박스·도메인/DNS·메시징·검색·라벨·웹훅·억제·첨부·이벤트)을
표준 MCP 툴로 다룰 수 있게 한다.

차별점: **HITL 승인 게이트 통합** — 발송이 승인 정책에 걸리면 `pending_approval` 로
큐잉되고, `approval_queue_list` / `message_approve` / `message_reject` 툴로 사람이
검토·결정한다.

> **transport**: local stdio 및 원격 Streamable HTTP 를 지원한다.
> 브라우저 OAuth 는 아래 운영 설정으로 선택 활성화한다. 공개 레지스트리/
> Smithery 등재와 routines·workflow marketplace·operator timeline 은 후속이다.

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
| `LOFTBOX_MCP_OAUTH_ENABLED` | | (미설정=비활성) | `true` 명시 시 브라우저 OAuth 브로커 활성화(아래 3종 필수). |
| `LOFTBOX_MCP_PUBLIC_URL` | OAuth 시 ✅ | — | 신뢰 HTTPS 공개 origin(예: `https://mcp.loftbox.net`). |
| `LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY` | OAuth 시 ✅ | — | 32바이트 base64 암호화 비밀(운영자 별도 주입). |
| `LOFTBOX_MCP_OAUTH_STORE` | OAuth 시 ✅ | — | durable 저장소 절대 경로(`/opt/loftbox-mcp` 밖). |
| `LOFTBOX_MCP_OAUTH_TRUSTED_PROXY_IPS` | | (미설정=신뢰 없음) | OAuth 속도 제한용 신뢰 프록시 exact IP(쉼표 구분, 기존 Caddy 루프백은 `127.0.0.1`). |

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

## 원격 웹 MCP (브라우저 OAuth)

Claude 웹·ChatGPT 웹에서 호스팅된 MCP URL 을 등록해 쓰는 브라우저 OAuth
연결을 지원한다(선택 활성화, 기본 비활성).

- 호스팅 URL(활성화 시): `https://mcp.loftbox.net/mcp`
  (`/`·`/setup` 에 연결 안내, `/health` 에 `oauth_enabled` 표기).
- Claude 웹: 커넥터 설정에 위 URL 입력 → 등록 방식에서
  **"Register automatically"(자동 등록)** 선택 → LoftBox 승인 화면에서
  기존 API 키로 승인.
- ChatGPT 웹: 개발자 모드 / 사용자 지정 MCP 커넥터(OAuth) 추가에서 위 URL
  입력(메뉴 제공 여부는 사용 중인 ChatGPT 클라이언트·워크스페이스에 따라
  다름) → 자동 클라이언트 등록 → 기존 API 키로 승인.
- 승인은 **기존에 발급받은 API 키를 연결**하는 것이다. 새 키를 발급하지
  않고 키 권한을 바꾸지 않으며, 원본 키는 암호화되어 이 서버에만 보관되고
  Claude/ChatGPT 에는 전달되지 않는다. 기존 로그인 세션으로 자동 연결되는
  SSO 가 아니다.
- 기본 권한은 읽기 전용(`loftbox.read`)이며, 관리(`loftbox.manage`)는 승인
  화면에서 직접 체크해야 부여되고(미체크 시 읽기로 축소) 신규 관리 설정
  도구만 추가된다. 메일 발송·승인·기존 쓰기 도구는 포함되지 않는다.
  실제 허용 여부는 키의 백엔드 scope 가 최종 판정한다.
- 커넥터 앱에서 연결을 제거해도 서버 승인이 항상 즉시 취소되지는 않는다.
  서버 승인을 확실히 끝내려면 사용한 API 키를 폐기하거나
  `/oauth/revoke`(RFC7009) 엔드포인트를 사용한다.

기술 메모: 공개 클라이언트 인가코드 + PKCE S256 + 회전 리프레시, 클라이언트
인증 방식 `none`, 동적 클라이언트 등록(DCR)만 지원한다. CIMD(client metadata
documents)는 지원하지 않으므로 Claude 설정에서 자동 등록을 선택해야 한다.
클라이언트 표시 이름은 미검증 입력으로 취급한다.

> **운영 상태**: 아래 활성화 설정은 운영자 전용이며, 실제 운영 OAuth 동작과
> 실제 Claude/ChatGPT 계정 연결은 아직 검증되지 않았다(로컬 합성 테스트만
> 통과). 활성화·배포는 별도 운영 승인이 필요하다. 상세는
> `deploy/DEPLOY.md` 와 `deploy/oauth.env.example` 을 본다.

### 로컬 합성 검증 (실제 키·외부 연결 없음)

```bash
npm run build
npm test
# fake API + 임시 저장소만 사용 — 외부 요청 없음.
# format/check/typecheck/build/test 전체는 "개발" 참고.
```

위 합성 테스트만으로 실제 운영 OAuth 동작이나 실제 Claude/ChatGPT 웹
계정 연결을 증명하지 않는다. 브라우저 승인·토큰·MCP 호출은 모두 로컬
합성 키·루프백으로만 검증된다.

### 운영자 구성 기동 예시 (합성 아님 — 별도 승인 필요)

아래는 운영자가 승인 후 VPS 에서 구성하는 형태의 예시이며, 합성
클라이언트 수락이 아니다. 실제 공개 URL·내부 API·비밀·영속 저장소가
필요하다.

```bash
npm run build
export LOFTBOX_MCP_OAUTH_ENABLED=true
export LOFTBOX_MCP_PUBLIC_URL=https://mcp.loftbox.net
export LOFTBOX_BASE_URL=http://localhost:8080
export LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY='<32바이트-base64-비밀>'
export LOFTBOX_MCP_OAUTH_STORE=/var/lib/loftbox-mcp/oauth/store.json
export LOFTBOX_MCP_OAUTH_TRUSTED_PROXY_IPS=127.0.0.1
node dist/http.js
# /health → oauth_enabled:true, /setup → 연결 안내
```

저장소 경로는 `/opt/loftbox-mcp` 밖이어야 한다(deploy.sh 가 그 디렉터리를
삭제한다). 암호화 비밀은 32바이트 base64 이며 운영자가 별도 주입한다
(형식은 `deploy/oauth.env.example` 참고, 평문 기록 금지).
저장소는 단일 프로세스 전제(원자적 쓰기·0600·전용 0700 디렉터리)이고,
용량 상한(클라이언트 2000·grant 10000·리프레시 20000·파일 32MiB) 초과 시
신규 등록·회전은 503 으로 거부되며 기존 grant 는 유지된다(유효 기록
추방 없음). 암호화 키 교체 시 기존 승인은 다시 받아야 한다(재승인 필요).
백업·복구와 Caddy/배포 절차는 `deploy/DEPLOY.md` 를 본다.

OAuth 속도 제한은 기본적으로 실제 소켓 피어 IP 로 버킷하므로, 기존
Caddy → `127.0.0.1:3100` 구성에서는 명시적 등록이 없으면 모든 사용자가
한 버킷에 묶인다. 운영자는 `LOFTBOX_MCP_OAUTH_TRUSTED_PROXY_IPS=127.0.0.1`
로 직접 프록시를 등록한다 — 이때만 신뢰 소켓 뒤 `X-Forwarded-For`
우측 IP 로 클라이언트를 분리한다(공식 Caddy `reverse_proxy` 가
설정·추가하는 헤더이며 수신된 미신뢰 전달값은 무시된다). 목록에 없는
소켓·루프백은 헤더 존재와 무관하게 절대 신뢰하지 않고, 비정상 헤더는
소켓 폴백한다. 형식 위반(호스트명·CIDR·빈 항목·초과) 시 기동이 중단된다.
이 설정은 OAuth 속도 제한에만 영향을 주고 host/origin/issuer/auth/context
및 MCP 트래픽 판정에는 쓰지 않는다.

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
운영자 절차로 별도 발급한다 — MCP 는 API 키를 발급하지 않으며, 브라우저
OAuth 는 기존 키 승인 브로커(별도 활성화, 위 "원격 웹 MCP" 참고)이다.

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
