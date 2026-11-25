/* Zetris entry page — external script (strict CSP).
   Separates platform operators from customer organizations. */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  async function api(path, payload) {
    const r = await fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || 'request failed');
    return body;
  }
  function msg(text, bad) {
    $('msg').textContent = text;
    $('msg').className = bad ? 'err' : 'msg';
  }

  $('operator-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    msg('signing in…');
    try {
      await api('/api/session', { token: $('operator-token').value });
      $('operator-token').value = '';
      location.href = '/operator';
    } catch (error) { msg(error.message, true); }
  });

  $('tenant-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    msg('opening tenant console…');
    try {
      const result = await api('/api/tenant/claim', {
        slug: $('tenant-slug').value, token: $('tenant-token').value });
      $('tenant-token').value = '';
      location.href = '/tenant/' + encodeURIComponent(result.tenant) +
        '?session=' + encodeURIComponent(result.session);
    } catch (error) { msg(error.message, true); }
  });

  $('signup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    msg('creating tenant…');
    try {
      const result = await api('/api/signup', {
        slug: $('new-slug').value, email: $('new-email').value, tier: $('new-tier').value });
      $('new-slug').value = ''; $('new-email').value = '';
      msg('tenant ' + result.slug + ' created. Use its handoff link when ready.', false);
    } catch (error) { msg(error.message, true); }
  });
})();
