/** OAuth 브라우저 UI — 의존성 없는 단일 HTML(인라인 CSS만).
 *
 * 모든 동적 값은 escapeHtml 을 거쳐 출력한다. 특히 DCR 로 등록된
 * 클라이언트 표시 이름은 미검증 입력이므로 "주장하는 이름"으로만 표기한다.
 */

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const BASE_CSS = `
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Noto Sans KR","Segoe UI",sans-serif;line-height:1.6;background:#f6f7f9;color:#1a1d21}
@media (prefers-color-scheme:dark){body{background:#121417;color:#e8eaed}}
.wrap{max-width:720px;margin:0 auto;padding:24px 16px 64px}
.card{background:#fff;border:1px solid #e2e5ea;border-radius:12px;padding:24px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}
@media (prefers-color-scheme:dark){.card{background:#1c1f24;border-color:#33373d}}
h1{font-size:1.5rem;margin:.2em 0}
h2{font-size:1.15rem;margin:1.2em 0 .4em}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;background:#eef1f4;padding:2px 6px;border-radius:6px;word-break:break-all}
@media (prefers-color-scheme:dark){code{background:#2a2e34}}
.url{font-size:1rem;word-break:break-all}
ol.steps{padding-left:1.3em}
ol.steps li{margin:.5em 0}
.badge{display:inline-block;font-size:.8rem;font-weight:700;padding:2px 10px;border-radius:999px;background:#e7f4ec;color:#137333}
.badge.off{background:#fdecea;color:#b3261e}
.note{font-size:.9rem;color:#5b6168}
@media (prefers-color-scheme:dark){.note{color:#a7adb4}}
.err{background:#fdecea;border:1px solid #f5c6c2;color:#8f1d17;border-radius:8px;padding:12px 14px;margin:12px 0}
@media (prefers-color-scheme:dark){.err{background:#3a1d1a;border-color:#6e3530;color:#ffb4ab}}
label.field{display:block;margin:14px 0}
label.field>span{display:block;font-weight:700;margin-bottom:6px}
input[type=text],input[type=password]{width:100%;padding:12px;border:1px solid #c9ced4;border-radius:8px;font-size:1rem;background:#fff;color:#111}
@media (prefers-color-scheme:dark){input[type=text],input[type=password]{background:#121417;border-color:#4a4f55;color:#eee}}
.check{display:flex;gap:10px;align-items:flex-start;margin:10px 0;padding:12px;border:1px solid #e2e5ea;border-radius:8px}
@media (prefers-color-scheme:dark){.check{border-color:#33373d}}
.check input{margin-top:4px}
.btns{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}
button{flex:1;min-width:140px;padding:13px 16px;border-radius:8px;font-size:1rem;font-weight:700;cursor:pointer;border:1px solid transparent}
.allow{background:#137333;color:#fff}
.allow:hover{background:#0f5c29}
.deny{background:#fff;border-color:#c9ced4;color:#333}
@media (prefers-color-scheme:dark){.deny{background:#1c1f24;color:#e8eaed;border-color:#4a4f55}}
.deny:hover{background:#f1f2f4}
@media (prefers-color-scheme:dark){.deny:hover{background:#2a2e34}}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 12px;font-size:.95rem;margin:10px 0}
.kv dt{color:#5b6168}
@media (prefers-color-scheme:dark){.kv dt{color:#a7adb4}}
.kv dd{margin:0;word-break:break-all}
footer{margin-top:32px;font-size:.85rem;color:#5b6168}
@media (prefers-color-scheme:dark){footer{color:#a7adb4}}
`;

function shell(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${BASE_CSS}</style>
</head>
<body>
<div class="wrap">
${body}
<footer>LoftBox MCP — 기존 API 키 연결 승인 전용입니다. 새 키를 발급하지 않습니다.</footer>
</div>
</body>
</html>`;
}

export interface SetupPageData {
  oauthEnabled: boolean;
  /** canonical 리소스 (활성 시). */
  resource: string | null;
  issuer: string | null;
}

export function renderSetupPage(d: SetupPageData): string {
  const status = d.oauthEnabled
    ? `<span class="badge">OAuth 연결 가능</span>`
    : `<span class="badge off">OAuth 비활성화</span>`;
  const urlBlock =
    d.oauthEnabled && d.resource
      ? `<p class="url"><code>${escapeHtml(d.resource)}</code></p>`
      : `<p class="note">현재 이 서버는 브라우저 OAuth 연결을 제공하지 않습니다.
         서버 운영자에게 OAuth 활성화(공개 URL·암호화 비밀·저장소 설정)를 요청하세요.
         기존 raw API 키 방식과 stdio 실행은 그대로 사용할 수 있습니다.</p>`;
  const body = `
<h1>LoftBox MCP 웹 연결 ${status}</h1>
<div class="card">
<h2>1. 연결 URL 등록</h2>
<p>Claude 웹 / ChatGPT 웹 커넥터 설정에 아래 MCP 서버 URL 을 입력합니다.</p>
${urlBlock}
</div>
<div class="card">
<h2>2. Claude 웹에서 연결하기</h2>
<ol class="steps">
<li>Claude 설정 → <b>커넥터(Connectors)</b> → <b>사용자 지정 커넥터 추가</b>를 엽니다.</li>
<li>위 MCP 서버 URL 을 입력하고 등록 방식에서
<b>"Register automatically"(자동 등록)</b>를 선택합니다.</li>
<li>LoftBox 승인 화면이 열리면 <b>기존에 발급받은 API 키</b>를 입력하고,
요청된 권한(읽기/관리)을 확인한 뒤 <b>허용</b>을 누릅니다.</li>
</ol>
<p class="note">참고: <a href="https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp">Claude 공식 안내: custom connectors</a></p>
</div>
<div class="card">
<h2>3. ChatGPT 웹에서 연결하기</h2>
<ol class="steps">
<li>ChatGPT 설정에서 개발자 모드 / 사용자 지정 MCP 커넥터(OAuth) 추가를 엽니다.
(메뉴 제공 여부는 사용 중인 ChatGPT 클라이언트·워크스페이스에 따라 다릅니다.)</li>
<li>MCP 서버 URL 을 입력하면 ChatGPT 가 이 서버에 OAuth 클라이언트를 자동으로 등록합니다.</li>
<li>LoftBox 승인 화면이 열리면 <b>기존 API 키</b>로 승인합니다.
콜백 주소는 ChatGPT 가 등록한 값 그대로 사용합니다.</li>
</ol>
<p class="note">참고: <a href="https://developers.openai.com/plugins/build/auth">OpenAI 공식 안내: auth</a> ·
<a href="https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP 인증 스펙(2025-11-25)</a></p>
</div>
<div class="card">
<h2>권한 안내</h2>
<dl class="kv">
<dt><code>loftbox.read</code></dt><dd>읽기 전용 도구만 사용합니다(조회·목록·상태 확인). 기본값입니다.</dd>
<dt><code>loftbox.manage</code></dt><dd>읽기에 더해 <b>관리 설정 도구</b>(도메인 검증·오디언스/발신프로필 설정·구독 동기화·키 폐기 등)만 추가됩니다.
메일 발송·승인·기존 쓰기 도구는 포함되지 않습니다. 승인 화면에서 직접 체크해야 부여되며, 체크하지 않으면 읽기로 축소됩니다.</dd>
</dl>
<p class="note">실제 허용 여부는 키가 가진 백엔드 scope 가 최종 판정합니다.
승인에는 최소 권한의 기존 키를 사용하세요.</p>
</div>
<div class="card">
<h2>연결 해제·취소</h2>
<p>커넥터 앱에서 연결을 제거해도 서버 쪽 승인이 항상 즉시 취소되는 것은 아닙니다.
서버 승인을 확실히 취소하려면 다음 중 하나를 사용하세요.</p>
<ul>
<li>사용한 API 키를 폐기(키 폐기 시 해당 연결은 즉시 중단됩니다).</li>
<li>OAuth 토큰 폐기 엔드포인트(<code>/oauth/revoke</code>, RFC7009).</li>
</ul>
</div>`;
  return shell("LoftBox MCP 웹 연결", body);
}

export interface AuthorizePageData {
  /** 폼 POST 대상(항상 /oauth/authorize). */
  txnId: string;
  csrfToken: string;
  /** 미검증 클라이언트 표시 이름 + client_id. */
  clientName: string | null;
  clientId: string;
  /** 콜백 호스트(사용자 확인용). */
  callbackHost: string;
  callbackUri: string;
  /** 요청된 scope. */
  requestedManage: boolean;
  orgHint: string | null;
  error: string | null;
  /** 듯: 관리 체크박스 표시 여부 = manage 가 요청된 경우. */
  manageChecked: boolean;
}

export function renderAuthorizePage(d: AuthorizePageData): string {
  const clientLabel = d.clientName
    ? `${escapeHtml(d.clientName)} (클라이언트가 주장하는 이름 — 미검증)`
    : `이름 없는 클라이언트 (미검증)`;
  const err = d.error
    ? `<div class="err" role="alert">${escapeHtml(d.error)}</div>`
    : "";
  const manageBlock = d.requestedManage
    ? `<div class="check"><input type="checkbox" id="allow_manage" name="allow_manage" value="yes"${d.manageChecked ? " checked" : ""}>
<label for="allow_manage"><b>관리 권한 허용 <code>loftbox.manage</code></b><br>
<span class="note">체크하지 않으면 <b>읽기 전용</b>으로 연결됩니다. 관리 권한은 도메인 검증·오디언스/발신프로필 설정·
구독 동기화·키 폐기 같은 관리 설정 도구만 추가하며, 메일 발송·승인 도구는 포함하지 않습니다.</span></label></div>`
    : `<p class="note">이 연결은 <b>읽기 전용</b>(<code>loftbox.read</code>)을 요청했습니다.</p>`;
  const body = `
<h1>LoftBox 연결 승인</h1>
<div class="card">
${err}
<p><b>${clientLabel}</b> 앱이 LoftBox MCP 연결을 요청했습니다.</p>
<dl class="kv">
<dt>콜백 주소</dt><dd><code>${escapeHtml(d.callbackUri)}</code><br>
<span class="note">호스트: ${escapeHtml(d.callbackHost)} — 예상한 Claude/ChatGPT 주소인지 확인하세요.</span></dd>
<dt>클라이언트 ID</dt><dd><code>${escapeHtml(d.clientId)}</code></dd>
</dl>
<form method="post" action="/oauth/authorize">
<input type="hidden" name="txn" value="${escapeHtml(d.txnId)}">
<input type="hidden" name="csrf" value="${escapeHtml(d.csrfToken)}">
<div class="check"><input type="checkbox" checked disabled>
<label><b>읽기 권한 <code>loftbox.read</code></b> (항상 포함)<br>
<span class="note">조회·목록·상태 확인 도구만 사용합니다.</span></label></div>
${manageBlock}
<label class="field"><span>기존 LoftBox API 키</span>
<input type="password" name="api_key" autocomplete="off" autocapitalize="off" spellcheck="false"
placeholder="lb_ 로 시작하는 기존 키를 입력하세요" maxlength="512" required></label>
<p class="note">입력한 키는 검증 후 암호화되어 이 서버에만 보관되고, Claude/ChatGPT 에는 전달되지 않습니다.
새 키를 발급하지 않으며 키 권한을 바꾸지도 않습니다. 최소 권한 키 사용을 권장합니다.</p>
<div class="btns">
<button class="allow" type="submit" name="decision" value="allow">허용</button>
<button class="deny" type="submit" name="decision" value="deny" formnovalidate>거부</button>
</div>
</form>
</div>`;
  return shell("LoftBox 연결 승인", body);
}

export function renderErrorPage(title: string, message: string): string {
  const body = `
<h1>${escapeHtml(title)}</h1>
<div class="card">
<div class="err" role="alert">${escapeHtml(message)}</div>
<p class="note">이 창을 닫고 클라이언트(Claude/ChatGPT) 설정에서 다시 시도하세요.
반복되면 서버 운영자에게 문의하세요. (요청 ID·시각을 함께 알려주면 진단에 도움이 됩니다.)</p>
</div>`;
  return shell(title, body);
}
