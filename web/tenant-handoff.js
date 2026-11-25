/* Tenant one-time handoff page — external script (strict CSP). */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const parts = location.pathname.split('/').filter(Boolean);
  const slug = parts[1] || '';
  const token = new URLSearchParams(location.search).get('token') || '';
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  async function api(path, options = {}) {
    const r = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || 'request failed');
    return body;
  }

  function card(label, url) {
    if (!url) return '';
    return `<a class="url-card" href="${esc(url)}" target="_blank" rel="noopener noreferrer">
      <span class="k">${esc(label)}</span><span class="v">${esc(url)}</span><span class="go">Open ↗</span></a>`;
  }

  async function load() {
    try {
      const data = await api('/api/handoff/' + encodeURIComponent(slug), {
        method: 'POST', body: JSON.stringify({ token })
      });
      $('tenant').textContent = data.tenant;
      $('email').textContent = data.administrator;
      $('password').textContent = data.admin_password;
      $('cards').innerHTML =
        card('Protected application', data.urls.app) +
        card('Audit console', data.urls.audit) +
        card('NetBird dashboard', data.urls.netbird);
      $('portal-link').href = '/tenant/' + encodeURIComponent(data.tenant) +
        '?session=' + encodeURIComponent(data.session);
      $('done').hidden = false;
      $('error').hidden = true;
    } catch (error) {
      $('error').textContent = error.message;
      $('error').hidden = false;
    }
  }
  load();
})();
