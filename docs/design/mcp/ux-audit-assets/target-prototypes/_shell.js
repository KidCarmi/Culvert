/* Shared shell for the MCP target prototypes. Renders the Culvert sidebar +
   topbar + the mandatory "DESIGN PROTOTYPE - NOT IMPLEMENTED" banner. No network,
   no production code. Pure static rendering from synthetic data. */

function qp(name, def) {
  const v = new URLSearchParams(location.search).get(name);
  return v == null ? def : v;
}

const MCP_NAV = [
  ['Command Center', 'command-center'],
  ['Investigations', 'activity'],
  ['MCP Assets', 'assets'],
  ['Policy & Simulation', 'policy'],
  ['Approvals & Allowances', 'approvals'],
  ['Health & Distribution', 'health'],
  ['Rollout & Exposure', 'rollout'],
  ['Production Qualification', 'qualification'],
  ['Administration', 'admin'],
];

function renderShell(opts) {
  const active = opts.active || '';
  const sidebar = document.getElementById('sidebar');
  sidebar.innerHTML = `
    <div class="logo">
      <div class="logo-icon">C</div>
      <div><div class="logo-text">Culvert</div><div class="logo-sub">MCP Gateway · prototype</div></div>
    </div>
    <nav>
      <div class="nav-section">Overview</div>
      <div class="nav-item"><span class="ico">▤</span>Dashboard</div>
      <div class="nav-section">MCP Gateway</div>
      ${MCP_NAV.map(([label, id]) => `
        <div class="nav-item ${id === active ? 'active' : ''}">
          <span class="ico">◇</span>${label}
          ${opts.attn && id === 'command-center' ? `<span class="nav-badge">${opts.attn}</span>` : ''}
        </div>`).join('')}
      <div class="nav-section">Platform</div>
      <div class="nav-item"><span class="ico">◈</span>Cluster</div>
      <div class="nav-item"><span class="ico">◈</span>Settings</div>
    </nav>
    <div class="sidebar-footer">
      <div class="status-row"><span class="dot green"></span><span>Gateway</span></div>
      <div class="status-row"><span class="dot ${opts.killed ? 'gray' : 'green'}"></span><span>Admission ${opts.killed ? 'stopped' : 'open'}</span></div>
    </div>`;

  const topbar = document.getElementById('topbar');
  const stale = opts.stale;
  topbar.innerHTML = `
    <div class="topbar-l">
      <div class="topbar-title">${opts.title || ''}</div>
      <div class="topbar-sub">${opts.sub || ''}</div>
    </div>
    <div class="topbar-r">
      <span class="pill live"><span style="width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block"></span>LIVE</span>
      <span class="asof ${stale ? 'stale' : ''}" style="font-size:.72rem">${stale ? '⚠ ' : ''}as-of ${opts.asof || '13:52:45'}</span>
      <span class="role-badge">ADMIN</span>
    </div>`;
}

function shellReady() { document.body.setAttribute('data-ready', '1'); }
