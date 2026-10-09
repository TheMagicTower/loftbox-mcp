# 원격 MCP RS 배포 (mcp.loftbox.net)

호스팅 remote MCP(Streamable HTTP, api_key bearer). VPS 에 systemd Node 서비스 +
Caddy TLS 리버스 프록시. **이 디렉토리가 source-of-truth — VPS 직접 핫픽스 금지.**

## 구성
| 파일 | VPS 위치 | 역할 |
|---|---|---|
| `loftbox-mcp.service` | `/etc/systemd/system/loftbox-mcp.service` | systemd 유닛(127.0.0.1:3100, node dist/http.js) |
| `Caddyfile.snippet` | `/etc/caddy/Caddyfile` 에 병합 | mcp.loftbox.net → localhost:3100, LE TLS |
| `deploy.sh` | (로컬 실행) | 소스→VPS 빌드→systemd→헬스, 멱등 |

## 사전 조건 (최초 1회)
1. VPS 에 Node ≥18 (NodeSource). 2. DNS: Cloudflare A `mcp.loftbox.net` → VPS IP, **proxied=false**(Caddy LE tls-alpn-01).
3. Caddy: `Caddyfile.snippet` 블록을 `/etc/caddy/Caddyfile` 에 추가 후 `systemctl reload caddy`(인증서 자동 발급).

## 배포/갱신 (매 릴리스)
```sh
VPS_HOST=root@<ip> SSH_KEY=~/.ssh/<key> bash deploy/deploy.sh
```
빌드는 VPS 에서(npm ci + tsc + dev prune). 런타임 deps = @modelcontextprotocol/sdk + zod 만(~30MB).

## env (systemd 유닛)
- `LOFTBOX_MCP_PORT=3100` / `LOFTBOX_MCP_HOST=127.0.0.1` (Caddy 뒤, 비공개)
- `LOFTBOX_BASE_URL=http://localhost:8080` (같은 박스 loftbox-api 내부 호출)
- OAuth(선택, 기본 비활성): `EnvironmentFile=-/etc/loftbox-mcp/oauth.env`
  (없으면 무시, `-` 접두). 아래 "브라우저 OAuth 활성화" 참고.

## 검증
- `curl http://127.0.0.1:3100/health` → 200 (로컬)
- `curl https://mcp.loftbox.net/health` → 200 (공개, LE 인증서)
- 실 api_key bearer 로 MCP initialize→tools/list (raw 45 툴,
  `LOFTBOX_MCP_READ_ONLY=true` 시 26 툴). 무효 키 → 401.
  OAuth 프로필은 read 26·manage 33(읽기+신규 관리 쓰기, 레거시 발송 제외).
- 비활성 기본: `/health` → `oauth_enabled:false`, `/`·`/setup` 에 비활성
  안내, `/oauth/*`·`/.well-known/oauth-*` → 404.

## 브라우저 OAuth 활성화 (운영자 전용, 별도 승인 필요)

Claude 웹·ChatGPT 웹이 `https://mcp.loftbox.net/mcp` 를 등록해 쓰는 기존
API 키 승인 브로커. **실제 운영 OAuth 동작과 실제 클라이언트 계정 연결은
아직 검증되지 않았다.** 아래 절차를 검토하고 별도 운영 승인을 받은 후
수행한다. 현재 tracked 유닛은 `User=` 지정이 없어 root 로 실행하므로 실제
서비스 사용자에 맞춰 파일·디렉터리 소유권을 설정한다.

1. 승인된 비밀 관리 경로에서 32바이트 난수를 생성하고 base64 로 주입한다.
   실제 값은 로그·채팅·셸 기록·소스 저장소에 출력하지 않고 운영자가 보관한다.
2. VPS 에 비밀 파일 배치(0600, 서비스 사용자 소유):
   `/etc/loftbox-mcp/oauth.env` — 형식은 `deploy/oauth.env.example` 참고.
   `LOFTBOX_MCP_OAUTH_ENABLED=true`,
   `LOFTBOX_MCP_PUBLIC_URL=https://mcp.loftbox.net`,
   `LOFTBOX_MCP_OAUTH_ENCRYPTION_KEY=<위 비밀>`,
   `LOFTBOX_MCP_OAUTH_STORE=/var/lib/loftbox-mcp/oauth-store.json`.
3. 저장소 디렉터리 준비(0700, 서비스 사용자 소유, `/opt/loftbox-mcp` 밖 —
   deploy.sh 가 `/opt/loftbox-mcp` 를 삭제한다):
   `mkdir -p /var/lib/loftbox-mcp && chmod 700 /var/lib/loftbox-mcp`.
   공유/타인 소유/심볼릭 링크 경로는 기동 시 거부된다.
4. `deploy.sh` 로 배포(유닛의 `EnvironmentFile=-...` 가 비밀을 읽음) 후
   `systemctl restart loftbox-mcp`.
5. 검증: `curl https://mcp.loftbox.net/health` → `oauth_enabled:true`;
   `/.well-known/oauth-protected-resource`·`/mcp` 가 canonical resource 와
   동일 issuer 를 가리키는지 확인. Caddy 변경 불필요(기존 프록시 유지,
   Host 전달 전제).

제약·운영 주의:

- 단일 프로세스 전제: 같은 저장소를 여러 프로세스가 쓰면 last-write-wins
  유실 가능. systemd 단일 인스턴스로만 운영한다.
- 암호화 키 교체·분실 시 기존 승인은 복호화 불가 → 사용자가 다시 승인해야
  한다(키 회전=재승인). 비밀 백업은 운영자 책임.
- 저장소 백업: 서비스 중지 후 파일 복사, 복구는 0600·소유자 확인 후 기동.
  평문 API 키·raw OAuth 토큰은 저장소에 기록되지 않는다(암호문·해시만).
- 활성화 상태에서 설정이 하나라도 유효하지 않으면 기동이 중단된다
  (fail-closed, 조용한 비활성 폴백 없음).
- 저장소 용량 상한: 클라이언트 2000·grant 10000·리프레시 20000·파일 32MiB.
  초과 시 신규 DCR·grant·회전은 원자적으로 503 거부되며(메모리·디스크 변경
  없음) 기존 grant·리프레시 재사용 증거(tombstone)는 추방되지 않는다.
  만료·폐기·고아만 안전 정리된다. 용량 해제는 만료·폐기 대기 또는 운영자
  점검 후 승인 정리로 수행한다.
- 클라이언트 연결은 사용자 수락 검증으로 남는다: Claude 웹 커넥터에 호스팅
  URL(`https://mcp.loftbox.net/mcp`) 등록 후 "Register automatically" 선택,
  ChatGPT 웹은 개발자 모드/워크스페이스 제공 메뉴에서 같은 URL 등록(메뉴
  제공 여부는 클라이언트·워크스페이스에 따라 다름), 이후 브라우저에서 기존
  API 키 승인. 연결 해제가 서버 grant 폐기를 보장하지 않으므로, 필요 시 키
  폐기 또는 `/oauth/revoke` 를 안내한다. 운영 OAuth 활성화·실제 웹 계정
  연결 수락은 별도 승인 후 진행하며, 코드·로컬 합성 테스트만으로 실제 연결을
  주장하지 않는다.

## 후속(별도)
- CI 자동배포(deploy-vps 류) 미구성 — 현재 deploy.sh 수동.
- 실제 운영 OAuth·실제 클라이언트 계정 연결 검증(사용자 수락).
