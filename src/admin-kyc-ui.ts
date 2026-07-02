/**
 * VERI admin/compliance dashboard (VERI-S4 UI) — a branded, server-rendered page at
 * GET /admin/kyc that lists KYC cases and lets an admin approve/reject a review with
 * one click. Same origin as the API, so the browser's OIDC session cookie authorizes
 * every fetch; the route + this page are both gated by KYC_ADMIN_SUBS.
 *
 * On-brand: self-hosted Space Grotesk / Geist / Geist Mono, warm-paper canvas,
 * evergreen header, citric-green accent — matching /verify and the SIWE login.
 */

export function renderAdminKycUI(): string {
  return `<!doctype html>
<html lang="en" data-theme="light"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0f2a1a">
<title>KYC compliance — Citrate</title>
<style>
@font-face { font-family:'Geist'; src:url('/fonts/Geist-Regular.woff2') format('woff2'); font-weight:400; font-display:swap; }
@font-face { font-family:'Geist'; src:url('/fonts/Geist-Medium.woff2') format('woff2'); font-weight:500; font-display:swap; }
@font-face { font-family:'Geist'; src:url('/fonts/Geist-SemiBold.woff2') format('woff2'); font-weight:600; font-display:swap; }
@font-face { font-family:'Geist Mono'; src:url('/fonts/GeistMono-Regular.woff2') format('woff2'); font-weight:400; font-display:swap; }
@font-face { font-family:'Geist Mono'; src:url('/fonts/GeistMono-Medium.woff2') format('woff2'); font-weight:500; font-display:swap; }
@font-face { font-family:'Space Grotesk'; src:url('/fonts/SpaceGrotesk.ttf') format('truetype'); font-weight:100 900; font-display:swap; }
:root {
  --font-display:'Space Grotesk',system-ui,sans-serif; --font-sans:'Geist',system-ui,sans-serif; --font-mono:'Geist Mono',ui-monospace,monospace;
  --canvas:#f1eee6; --surface:#faf8f3; --surface-2:#ffffff; --surface-sunk:#ecebe4; --border:#dbdcd5; --border-strong:#c3c4be;
  --text-1:#0e0f0c; --text-2:#555851; --text-3:#8a8c84; --accent:#8ecc09; --accent-fg:#112005; --accent-tint:#e8f3c6;
  --success:#4f8a05; --success-bg:#ecf5d4; --danger:#a72414; --danger-bg:#f6e1de; --amber:#8a6b05; --amber-bg:#fbf0cc;
  --header-bg:#0f2a1a; --header-fg:#f1eee6; --header-fg-2:#9db8a6; --r-1:6px; --r-2:9px; --tr:0.14em;
}
* { box-sizing:border-box; } html,body { margin:0; padding:0; }
body { background:var(--canvas); color:var(--text-1); font-family:var(--font-sans); font-size:15px; line-height:1.5; -webkit-font-smoothing:antialiased; }
.brand { display:flex; align-items:center; gap:.6rem; background:var(--header-bg); color:var(--header-fg); padding:.85rem 1.5rem; }
.brand .mark { width:22px; height:22px; border-radius:5px; background:var(--accent); box-shadow:0 0 0 3px rgba(142,204,9,.18); }
.brand .word { font-family:var(--font-display); font-weight:600; letter-spacing:-.01em; font-size:15px; }
.brand .tag { font-family:var(--font-mono); font-size:10px; letter-spacing:var(--tr); text-transform:uppercase; color:var(--header-fg-2); margin-left:auto; }
.wrap { max-width:72rem; margin:0 auto; padding:1.5rem; }
h1 { font-family:var(--font-display); font-weight:500; font-size:26px; letter-spacing:-.015em; margin:.5rem 0 .25rem; }
.sub { color:var(--text-2); font-size:14px; margin:0 0 1.25rem; }
.tabs { display:flex; gap:.4rem; margin-bottom:1rem; }
.tabs button { font-family:var(--font-mono); font-size:11px; letter-spacing:.06em; text-transform:uppercase; height:32px; padding:0 12px; border-radius:var(--r-1); border:1px solid var(--border); background:var(--surface-2); color:var(--text-2); cursor:pointer; }
.tabs button.on { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); font-weight:600; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:var(--r-2); overflow:hidden; box-shadow:0 14px 38px -18px rgba(14,15,12,.30); }
table { width:100%; border-collapse:collapse; font-size:13.5px; }
thead th { font-family:var(--font-mono); font-size:10px; letter-spacing:var(--tr); text-transform:uppercase; color:var(--text-3); text-align:left; padding:.7rem 1rem; border-bottom:1px solid var(--border); background:var(--surface-sunk); }
tbody td { padding:.7rem 1rem; border-bottom:1px solid var(--border); vertical-align:middle; }
tbody tr:last-child td { border-bottom:0; }
.mono { font-family:var(--font-mono); font-size:12px; color:var(--text-2); }
.badge { display:inline-block; font-family:var(--font-mono); font-size:10px; letter-spacing:.05em; text-transform:uppercase; padding:.2rem .5rem; border-radius:999px; font-weight:500; }
.b-pending { background:var(--amber-bg); color:var(--amber); } .b-verified { background:var(--success-bg); color:var(--success); }
.b-rejected { background:var(--danger-bg); color:var(--danger); } .b-created,.b-review { background:var(--surface-sunk); color:var(--text-2); }
.act button { height:32px; padding:0 12px; border-radius:var(--r-1); font-family:var(--font-sans); font-weight:600; font-size:12.5px; cursor:pointer; border:1px solid; }
.act .approve { background:var(--accent); color:var(--accent-fg); border-color:var(--accent); }
.act .reject { background:var(--surface-2); color:var(--danger); border-color:var(--border-strong); margin-left:.35rem; }
.act button:hover { filter:brightness(1.04); }
.empty { padding:2.5rem 1rem; text-align:center; color:var(--text-3); }
.foot { color:var(--text-3); font-size:12px; margin-top:1rem; }
</style></head>
<body>
<header class="brand"><span class="mark"></span><span class="word">Citrate</span><span class="tag">Compliance</span></header>
<div class="wrap">
  <h1>KYC cases</h1>
  <p class="sub">Review and adjudicate in-house identity verifications. Approving mints the baseline entitlement; the biometric is destroyed on decision.</p>
  <div class="tabs" id="tabs">
    <button data-s="pending" class="on">Pending</button>
    <button data-s="">All</button>
    <button data-s="verified">Verified</button>
    <button data-s="rejected">Rejected</button>
  </div>
  <div class="card"><table>
    <thead><tr><th>Subject</th><th>Status</th><th>Decision</th><th>Screening</th><th>Created</th><th>Action</th></tr></thead>
    <tbody id="rows"><tr><td colspan="6" class="empty">Loading…</td></tr></tbody>
  </table></div>
  <p class="foot" id="foot"></p>
</div>
<script>
(() => {
  const rows = document.getElementById('rows'), foot = document.getElementById('foot');
  let filter = 'pending';
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const fmt = (t) => { try { return new Date(t).toLocaleString(); } catch { return String(t); } };
  const badge = (s) => '<span class="badge b-' + esc(s) + '">' + esc(s) + '</span>';

  async function load() {
    rows.innerHTML = '<tr><td colspan="6" class="empty">Loading…</td></tr>';
    try {
      const r = await fetch('/admin/kyc/cases' + (filter ? '?status=' + filter : ''), { credentials: 'same-origin' });
      if (r.status === 403) { rows.innerHTML = '<tr><td colspan="6" class="empty">Not authorized — sign in as an admin (KYC_ADMIN_SUBS).</td></tr>'; return; }
      const { cases } = await r.json();
      if (!cases || !cases.length) { rows.innerHTML = '<tr><td colspan="6" class="empty">No ' + esc(filter || '') + ' cases.</td></tr>'; foot.textContent = ''; return; }
      rows.innerHTML = cases.map((c) => {
        const canAct = c.status === 'pending';
        const act = canAct
          ? '<div class="act"><button class="approve" data-id="' + esc(c.caseId) + '" data-d="verified">Approve</button>'
            + '<button class="reject" data-id="' + esc(c.caseId) + '" data-d="rejected">Reject</button></div>'
          : '<span class="mono">—</span>';
        return '<tr><td class="mono" title="' + esc(c.caseId) + '">' + esc((c.externalUserId || '').slice(0, 12)) + '…</td>'
          + '<td>' + badge(c.status) + '</td>'
          + '<td class="mono">' + esc(c.decision || '—') + '</td>'
          + '<td class="mono">' + esc(c.screeningResult || '—') + '</td>'
          + '<td class="mono">' + fmt(c.createdAt) + '</td>'
          + '<td>' + act + '</td></tr>';
      }).join('');
      foot.textContent = cases.length + ' case(s).';
    } catch (e) { rows.innerHTML = '<tr><td colspan="6" class="empty">Error: ' + esc(e.message || e) + '</td></tr>'; }
  }

  rows.addEventListener('click', async (ev) => {
    const b = ev.target.closest('button[data-id]'); if (!b) return;
    const caseId = b.getAttribute('data-id'), decision = b.getAttribute('data-d');
    const reason = decision === 'rejected' ? (prompt('Reason for rejection?') || 'rejected by admin') : 'approved by admin';
    b.disabled = true;
    try {
      const r = await fetch('/admin/kyc/adjudicate', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ caseId, decision, reason }) });
      const j = await r.json();
      if (!r.ok) { alert('Failed: ' + (j.reason || j.error || r.status)); b.disabled = false; return; }
      load();
    } catch (e) { alert('Error: ' + (e.message || e)); b.disabled = false; }
  });

  document.getElementById('tabs').addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-s]'); if (!b) return;
    filter = b.getAttribute('data-s');
    for (const t of document.querySelectorAll('#tabs button')) t.classList.toggle('on', t === b);
    load();
  });

  load();
  setInterval(load, 8000);
})();
</script>
</body></html>`;
}
