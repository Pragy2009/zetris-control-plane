/* Zetris Security Control Plane — external script (strict CSP: script-src 'self').
   Every displayed value comes from the backend store or its real step records. */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const PAGE_SIZE = 5;
  let tenants = [];
  let page = 0;

  const esc = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  async function api(path, options = {}) {
    const response = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || 'request failed');
    return body;
  }

  const time = (epoch) => epoch
    ? new Date(epoch * 1000).toLocaleTimeString('en-GB', { hour12: false })
    : '—';

  function badge(status) {
    const kind = status === 'ready' ? 'b-ready' : status === 'failed' ? 'b-failed' : 'b-other';
    return `<span class="badge ${kind}">${esc(status)}</span>`;
  }

  function draw() {
    const body = $('rows');
    const pages = Math.max(1, Math.ceil(tenants.length / PAGE_SIZE));
    page = Math.min(page, pages - 1);
    const visible = tenants.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

    if (!visible.length) {
      body.innerHTML = '<tr><td colspan="5" class="empty">No tenants yet — provision your first one.</td></tr>';
    } else {
      body.innerHTML = visible.map((tenant) => {
        const steps = tenant.records || [];
        const done = steps.filter((item) => item.status === 'ok').length;
        const progress = steps.length ? Math.round((done / steps.length) * 100) : 0;
        const detail = steps.length
          ? steps.map((item) => item.step + ': ' + item.status).join(' · ')
          : 'awaiting first step';
        const id = esc(tenant.slug);
        return `<tr>
          <td class="svc">${id}</td>
          <td>${esc(tenant.tier)}</td>
          <td>${badge(tenant.status)}</td>
          <td class="steps">${esc(detail)}<div class="prog"><i style="width:${progress}%"></i></div></td>
          <td><div class="act">
            <button data-action="suspend" data-slug="${id}">Stop</button>
            <button data-action="resume" data-slug="${id}">Start</button>
            <button data-action="backup" data-slug="${id}">Backup</button>
            <button data-action="setup-key" data-slug="${id}">Key</button>
            <button data-action="rotate" data-slug="${id}">Rotate</button>
            <button data-action="handoff" data-slug="${id}">Handoff</button>
            <button class="warn" data-action="delete" data-slug="${id}">Delete</button>
          </div></td>
        </tr>`;
      }).join('');
    }
    $('page-info').textContent = tenants.length
      ? `${page + 1}/${pages} · ${tenants.length} tenants`
      : '0 tenants';
    $('prev').disabled = page === 0;
    $('next').disabled = page >= pages - 1;
  }

  function drawState(state) {
    $('clock').textContent = time(state.server_time);
    $('s-mode').textContent = esc(state.mode);
    $('s-change').textContent = time(state.last_change);
    $('s-users').textContent = state.users;
    $('s-apps').textContent = state.apps;

    const metrics = $('metrics');
    metrics.innerHTML = `
      <div class="glass metric"><div class="k">Total tenants</div><div class="v">${state.tenants} <small>registered</small></div></div>
      <div class="glass metric"><div class="k">Provisioning</div><div class="v">${state.statuses.queued + state.statuses.provisioning} <small>in progress</small></div></div>
      <div class="glass metric"><div class="k">Ready</div><div class="v">${state.statuses.ready} <small>operational</small></div></div>`;

    const stages = Object.entries(state.pipeline);
    $('pipeline').innerHTML = stages.length
      ? stages.map(([name, counts]) =>
          `<span class="pipe ${counts.ok + counts.failed + counts.skipped === 0 ? 'zero' : ''}">${esc(name)} <b>${counts.ok}</b>${counts.failed ? ' / <b style="color:#fb7185">' + counts.failed + '</b>' : ''}</span>`
        ).join('')
      : '<span class="empty">no provisioning records yet</span>';
  }

  async function refresh() {
    try {
      const [listResult, state] = await Promise.all([api('/api/tenants'), api('/api/state')]);
      tenants = listResult.tenants;
      drawState(state);
      draw();
    } catch (error) {
      $('msg').textContent = 'backend unreachable: ' + error.message;
    }
  }

  async function act(slug, action) {
    $('msg').textContent = action + '…';
    try {
      const result = await api('/api/tenants/' + encodeURIComponent(slug) + '/' + action,
        { method: 'POST', body: '{}' });
      if (action === 'handoff' && result.handoff_url) {
        window.open(result.handoff_url, '_blank', 'noopener');
      }
      const key = action === 'setup-key' ? ' · key ' + result.result.one_time_setup_key : '';
      $('msg').textContent = action + ': ' + result.mode + ' (' + result.planned_operations + ' ops)' + key;
      refresh();
    } catch (error) {
      $('msg').textContent = error.message;
    }
  }

  document.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action]');
    if (button) act(button.dataset.slug, button.dataset.action);
  });
  $('prev').addEventListener('click', () => { page -= 1; draw(); });
  $('next').addEventListener('click', () => { page += 1; draw(); });

  $('f').addEventListener('submit', async (event) => {
    event.preventDefault();
    $('msg').textContent = 'provisioning…';
    try {
      await api('/api/signup', {
        method: 'POST',
        body: JSON.stringify({ slug: $('slug').value, email: $('email').value, tier: $('tier').value })
      });
      $('msg').textContent = 'tenant created; provisioning started.';
      $('slug').value = '';
      $('email').value = '';
      refresh();
    } catch (error) {
      $('msg').textContent = error.message;
    }
  });

  // Cursor-following ambient glow. Decoration only: sets CSS coordinates,
  // never reads or writes application data.
  window.addEventListener('pointermove', (event) => {
    document.documentElement.style.setProperty('--mx', event.clientX + 'px');
    document.documentElement.style.setProperty('--my', event.clientY + 'px');
  }, { passive: true });

  $('user-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const slug = tenants.length ? tenants[0].slug : '';
    if (!slug) { $('msg').textContent = 'Create a tenant first.'; return; }
    try {
      const result = await api('/api/tenants/' + slug + '/users', {
        method: 'POST',
        body: JSON.stringify({ email: $('invite-email').value, role: $('invite-role').value })
      });
      $('msg').textContent = 'user invited · one-time password: ' + result.result.one_time_password;
      $('invite-email').value = '';
      refresh();
    } catch (error) { $('msg').textContent = error.message; }
  });

  $('app-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const slug = tenants.length ? tenants[0].slug : '';
    if (!slug) { $('msg').textContent = 'Create a tenant first.'; return; }
    try {
      await api('/api/tenants/' + slug + '/apps', {
        method: 'POST',
        body: JSON.stringify({ id: $('app-id').value, host: $('app-host').value,
                               groups: ['tenant-http'], kinds: ['workspace'] })
      });
      $('msg').textContent = 'application added and policy re-rendered.';
      $('app-id').value = ''; $('app-host').value = '';
      refresh();
    } catch (error) { $('msg').textContent = error.message; }
  });

  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await api('/api/session', { method: 'POST',
        body: JSON.stringify({ token: $('operator-token').value }) });
      $('operator-token').value = '';
      $('login').hidden = true;
      refresh();
    } catch (error) { $('msg').textContent = error.message; }
  });

  async function checkAuth() {
    try {
      const result = await api('/api/me');
      $('login').hidden = result.authenticated;
      if (result.authenticated) refresh();
    } catch (error) { $('login').hidden = false; }
  }

  checkAuth();
  setInterval(checkAuth, 15000);
  setInterval(refresh, 1500);
})();
