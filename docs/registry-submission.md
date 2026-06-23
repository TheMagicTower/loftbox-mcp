# MCP 레지스트리 등재 가이드 (#279 GEO-15/16)

`@loftbox/mcp` 를 주요 MCP 레지스트리에 등재해 AI 검색/도구 디스커버리에서 발견되게 한다.
메타데이터 파일은 repo 에 준비됨(`server.json`, `smithery.yaml`). 계정·인증이 필요한 제출은
운영자(Erik)가 처리.

## 패키지 사실 (제출 시 공통)

- **이름**: `@loftbox/mcp` (npm), 공식 레지스트리 네임스페이스 `io.github.themagictower/loftbox-mcp`
- **실행**: `npx -y @loftbox/mcp` (stdio) · 원격 Streamable HTTP transport 도 포함
- **필수 env**: `LOFTBOX_API_KEY` (lb_…, secret) · 선택 `LOFTBOX_BASE_URL`(기본 https://api.loftbox.net)
- **저장소**: https://github.com/TheMagicTower/loftbox-mcp
- **카테고리/태그**: email, ai-agents, productivity, communication, mcp
- **한 줄 소개**: "Email infrastructure for AI agents — mailboxes, domains, messaging, and a
  human-in-the-loop approval queue, as MCP tools."

### 클라이언트 설정(붙여넣기용)

```json
{
  "mcpServers": {
    "loftbox": {
      "command": "npx",
      "args": ["-y", "@loftbox/mcp"],
      "env": { "LOFTBOX_API_KEY": "lb_..." }
    }
  }
}
```

## 레지스트리별 등재 방법

### 1. 공식 MCP Registry (registry.modelcontextprotocol.io)
- 파일: **`server.json`**(repo 루트, 준비됨).
- 방법: `mcp-publisher` CLI 로 게시 — 네임스페이스 `io.github.themagictower/*` 는 **GitHub 인증**으로
  소유권 검증.
  ```bash
  # 운영자(Erik): GitHub 로그인 후
  npx @modelcontextprotocol/publisher login github
  npx @modelcontextprotocol/publisher publish   # server.json 사용
  ```
- 검증: registry API 에서 `io.github.themagictower/loftbox-mcp` 조회.

### 2. Smithery (smithery.ai)
- 파일: **`smithery.yaml`**(repo 루트, 준비됨) — stdio + LOFTBOX_API_KEY config schema.
- 방법: smithery.ai 에서 **GitHub repo 연결** → 자동 빌드/등재. (또는 "Add Server" → repo 지정.)
- 계정·repo 연결 필요(운영자).

### 3. mcp.so
- 방법: mcp.so 의 "Submit" 폼에 repo URL + 위 메타데이터 입력. (대개 npm/GitHub 자동 인덱싱 + 폼 보강.)

### 4. Glama (glama.ai/mcp) · PulseMCP (pulsemcp.com)
- 대개 npm/GitHub 에서 **자동 인덱싱**(README/package.json 기반). 누락 시 각 사이트 제출 폼.
- README 의 설치 안내·도구 목록이 인덱싱 품질을 좌우 → 최신 유지.

## 자율 준비 완료 / 운영자 액션

- ✅ **준비(코드)**: `server.json`, `smithery.yaml`, 본 가이드.
- ⏳ **운영자(Erik)**: ① 공식 registry `mcp-publisher` GitHub 인증 게시, ② Smithery repo 연결,
  ③ mcp.so/기타 폼 제출. (계정·소유권 인증이 필요해 자동화 불가.)
