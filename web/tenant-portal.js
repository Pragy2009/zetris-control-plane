/* Tenant-facing management portal — external script (strict CSP). */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const parts = location.pathname.split('/').filter(Boolean);
  const slug = parts[1] || '';
  const session = new URLSearchParams(location.search).get('session') || '';
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  async function api(path, options = {}) {
    const separator = path.includes('?') ? '&' : '?';
    const url = path + separator + 'session=' + encodeURIComponent(session);
    const r = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options });
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || 'request failed');
    return body;
  }

  function status(value) {
    const cls = value === 'ready' ? 'ok' : value === 'failed' ? 'bad' : '';
    return `<span class="badge ${cls}">${esc(value)}</span>`;
  }

  async function refresh() {
    try {
      const [me, state] = await Promise.all([api('/api/tenant/me'), api('/api/tenant/state')]);
      $('tenant').textContent = me.slug;
      $('tier').textContent = me.tier;
      $('status').innerHTML = status(me.status);
      $('m-users').textContent = state.users + ' / ' + state.user_limit;
      $('m-apps').textContent = state.apps + ' / ' + state.app_limit;
      $('cards').innerHTML = [
        ['Application', state.urls.app],
        ['Audit console', state.urls.audit],
        ['NetBird', state.urls.netbird]
      ].map(([label, url]) => `<a class="url-card" href="${esc(url)}" target="_blank" rel="noopener noreferrer">
        <span class="k">${esc(label)}</span><span class="v">${esc(url)}</span><span class="go">Open ↗</span></a>`).join('');
      const toggles = $('toggles');
      toggles.innerHTML = Object.entries(state.features).map(([name, value]) =>
        `<label class="toggle"><input type="checkbox" data-feature="${esc(name)}" ${value ? 'checked' : ''}> ${esc(name)}</label>`
      ).join('');
    } catch (error) {
      $('error').textContent = error.message;
      $('error').hidden = false;
    }
  }

  async function submit(formId, endpoint, payload) {
    $('error').hidden = true;
    try {
      const result = await api(endpoint, { method: 'POST', body: JSON.stringify(payload) });
      $('msg').textContent = endpoint.endsWith('users')
        ? 'invited · one-time password: ' + result.result.one_time_password
        : endpoint.endsWith('setup-key')
          ? 'setup key: ' + result.result.one_time_setup_key
          : 'saved (' + result.mode + ')';
      formReset(formId);
      refresh();
    } catch (error) {
      $('msg').textContent = error.message;
    }
  }
  function formReset(id) { const f = $(id); if (f) f.reset(); }

  $('user-form').addEventListener('submit', (e) => {
    e.preventDefault();
    submit('user-form', '/api/tenant/users', { email: $('invite-email').value, role: $('invite-role').value });
  });
  $('app-form').addEventListener('submit', (e) => {
    e.preventDefault();
    submit('app-form', '/api/tenant/apps', {
      id: $('app-id').value, host: $('app-host').value,
      groups: ['tenant-http'], kinds: ['workspace'] });
  });
  $('setup-key').addEventListener('click', () => submit(null, '/api/tenant/setup-key', {}));
  $('toggles').addEventListener('change', (e) => {
    const name = e.target.dataset.feature;
    if (name) submit(null, '/api/tenant/features', { name, value: e.target.checked });
  });

  refresh();
  setInterval(refresh, 3000);
})();
