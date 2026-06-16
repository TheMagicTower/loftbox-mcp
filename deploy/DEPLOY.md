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

## 검증
- `curl http://127.0.0.1:3100/health` → 200 (로컬)
- `curl https://mcp.loftbox.net/health` → 200 (공개, LE 인증서)
- 실 api_key bearer 로 MCP initialize→tools/list (28 툴). 무효 키 → 401.

## 후속(별도)
- CI 자동배포(deploy-vps 류) 미구성 — 현재 deploy.sh 수동.
