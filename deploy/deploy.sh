#!/usr/bin/env bash
# deploy/deploy.sh — 원격 MCP RS 를 VPS 에 배포/갱신. 멱등.
# 로컬에서 소스 tarball → VPS 빌드 → systemd. root SSH 필요.
# 사용: VPS_HOST=root@<ip> SSH_KEY=~/.ssh/<key> bash deploy/deploy.sh
set -euo pipefail
: "${VPS_HOST:?VPS_HOST=root@<ip> 필요}"
SSH_KEY="${SSH_KEY:-}"
SSH=(ssh); SCP=(scp); [ -n "$SSH_KEY" ] && { SSH=(ssh -i "$SSH_KEY"); SCP=(scp -i "$SSH_KEY"); }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/4] 소스 tarball"
tar --exclude=node_modules --exclude=.git --exclude=dist -czf /tmp/loftbox-mcp-src.tgz -C "$ROOT" .
"${SCP[@]}" /tmp/loftbox-mcp-src.tgz "$VPS_HOST":/tmp/

echo "[2/4] VPS 빌드(npm ci + build + prune)"
"${SSH[@]}" "$VPS_HOST" 'set -e
  command -v node >/dev/null || { echo "node 미설치 — NodeSource 로 설치 필요"; exit 1; }
  rm -rf /opt/loftbox-mcp && mkdir -p /opt/loftbox-mcp
  tar -xzf /tmp/loftbox-mcp-src.tgz -C /opt/loftbox-mcp
  cd /opt/loftbox-mcp && npm ci && npm run build && npm prune --omit=dev
  test -f dist/http.js'

echo "[3/4] systemd 유닛 설치 + 재시작"
"${SCP[@]}" "$ROOT/deploy/loftbox-mcp.service" "$VPS_HOST":/etc/systemd/system/loftbox-mcp.service
"${SSH[@]}" "$VPS_HOST" 'systemctl daemon-reload && systemctl enable --now loftbox-mcp && sleep 2 && systemctl restart loftbox-mcp'

echo "[4/4] 헬스체크"
"${SSH[@]}" "$VPS_HOST" 'curl -fsS http://127.0.0.1:3100/health && echo'
echo "완료. Caddy(mcp.loftbox.net)·DNS 는 최초 1회 deploy/DEPLOY.md 참고."
