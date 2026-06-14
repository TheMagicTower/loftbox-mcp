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

## 툴 (28)

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
`openWorldHint`)로 부수효과를 알린다.

> 웹훅 등록(`webhook_create`)은 signing secret 이 1회만 반환되고 MCP 결과/로그
> 어디로도 흘리면 유출 표면이 되므로 1차에서 제외했다. secret 안전 전달 설계 후 후속.

## 권한(scope) 주의

다음 툴은 **admin scope API 키**가 필요하다. 키 권한이 부족하면 명확한 403 안내를
반환한다(서버는 죽지 않음):

- `message_approve`, `message_reject`
- `approval_policy_create`
- `suppression_add`, `suppression_remove`

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
