'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const {Simulation, simulationRoute, proxyControl, validateWorkerControl} = require('./simulation');
const simulationHTML = fs.readFileSync(path.join(__dirname, 'simulation.html'), 'utf8');
const simulationJS = fs.readFileSync(path.join(__dirname, 'simulation-ui.js'), 'utf8');

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

function createServer(options = {}) {
  const simulation = options.simulation || new Simulation();
  return http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (!['GET', 'HEAD', 'POST'].includes(req.method)) {
      res.writeHead(405, {Allow: 'GET, HEAD'});
      return res.end();
    }
    const pathname = req.url.split('?')[0];
    if (req.method === 'POST' && !pathname.startsWith('/simulation/')) {
      res.writeHead(405, {Allow: 'GET, HEAD'}); return res.end();
    }
    if (pathname === '/healthz' || pathname === '/healthz/') {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      return res.end(req.method === 'HEAD' ? '' : 'ok');
    }
    if (process.env.ZETRIS_DEMO_WORKER === 'true' && !validateWorkerControl(req,simulation)) {
      res.writeHead(403); return res.end('Private simulation controller required');
    }
    // /signout and /signed-out are owned by Envoy, before app authorization.
    // They must never depend on this backend or on an inline browser script.
    // The private Envoy route supplies these headers. No public backend port
    // is published; these headers are not themselves a login mechanism.
    const user = req.headers['x-current-user'];
    const tenant = req.headers['x-tenant-id'];
    if (!user || !tenant || !req.headers['x-session-id']) {
      res.writeHead(403, {'Content-Type': 'text/plain'});
      return res.end('Access through the authenticated Zetris gateway is required.');
    }
    if (process.env.ZETRIS_DEMO_WORKER_URL && /^\/simulation\/(status|run|stop)$/.test(pathname)) {
      proxyControl(req,res,pathname,process.env.ZETRIS_DEMO_WORKER_URL);req.resume();return;
    }
    if (simulationRoute(req, res, pathname, simulation)) { req.resume(); return; }
    if (req.method === 'POST') { res.writeHead(405, {Allow: 'GET, HEAD'}); return res.end(); }
    if (pathname === '/simulation' || pathname === '/simulation.js') {
      if (user !== 'zetris-admin') { res.writeHead(403); return res.end('Operator required'); }
      if (pathname === '/simulation.js') {
        res.writeHead(200, {'Content-Type':'application/javascript'});
        return res.end(req.method === 'HEAD' ? '' : simulationJS);
      }
      res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
      res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
      return res.end(req.method === 'HEAD' ? '' : simulationHTML);
    }
    if (pathname !== '/' && pathname !== '/index.html') {
      res.writeHead(404, {'Content-Type': 'text/plain'});
      return res.end('Not found');
    }
    const values = {TENANT: tenant, USER: user, HOST: req.headers.host || ''};
    const page = html.replace(/\{\{(TENANT|USER|HOST)\}\}/g, (_, key) => escapeHTML(values[key]));
    res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
    res.end(req.method === 'HEAD' ? '' : page);
  });
}
if (require.main === module) {
  createServer().listen(3000, '0.0.0.0', () => console.log('Zetris Workspace listening on :3000'));
}
module.exports = {createServer};
