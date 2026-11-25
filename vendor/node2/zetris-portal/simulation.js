'use strict';
// The worker sends real authenticated traffic through public Envoy ingress.
// It has only the dedicated simulation client's credential, never admin/DB keys.
const fs = require('node:fs');
const {randomUUID,timingSafeEqual} = require('node:crypto');
const SIM_USER = 'service-account-zetris-risk-simulator';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function validateConfig(config) {
  const suffix = '.ztna.sc.deeptrustxai.com';
  for (const key of ['appOrigin', 'auditOrigin']) {
    const url = new URL(config[key]);
    if (url.protocol !== 'https:' || url.origin !== config[key] || url.port || !url.hostname.endsWith(suffix)) throw Error('Invalid demo origin');
  }
  const tenant2 = config.tenant === 'ztna-tenant-2';
  if (!['ztna', 'ztna-tenant-2'].includes(config.tenant) ||
      config.appOrigin !== `https://${tenant2 ? 'tenant2-app' : 'app'}${suffix}` ||
      config.auditOrigin !== `https://${tenant2 ? 'tenant2-audit' : 'audit'}${suffix}` ||
      config.issuer !== `https://auth${suffix}/realms/${config.tenant}` ||
      config.clientId !== 'zetris-risk-simulator') throw Error('Wrong simulation tenant');
  return config;
}

class Simulation {
  constructor(options = {}) {
    this.configPath = options.configPath || '/run/zetris-demo/config.json';
    this.fetch = options.fetch || fetch;
    this.sleep = options.sleep || sleep;
    this.now = options.now || Date.now;
    this.state = {phase: 'idle', message: 'Ready for an operator to start a demonstration.'};
    this.running = false;
  }
  config() { return validateConfig(JSON.parse(fs.readFileSync(this.configPath, 'utf8'))); }
  async request(url, options = {}) {
    const response = await this.fetch(url, {...options, redirect: 'manual', signal: AbortSignal.timeout(15000)});
    if (response.status >= 300 && response.status < 400) { await response.body?.cancel(); throw Error('Unexpected redirect; demo stopped.'); }
    return response;
  }
  async json(url, options) {
    const response = await this.request(url, options);
    if (response.status !== 200) { await response.body?.cancel(); throw Error(`Protected demo endpoint returned HTTP ${response.status}.`); }
    return response.json();
  }
  start(config) {
    if (this.running) throw Error('A demonstration is already running.');
    this.running = true;
    this.cancelled = false;
    this.state = {run: randomUUID(), phase: 'starting', started: new Date(this.now()).toISOString(),
      normalSent: 0, probesSent: 0, success: false, message: 'Obtaining a dedicated simulation session.'};
    this.completion = this.execute(config).catch(error => {
      this.state.failureStage=this.state.phase;
      const message=String(error?.message||'');
      const safe=/^(Protected demo endpoint returned HTTP [0-9]+\.|Unexpected redirect; demo stopped\.|Simulation token lifetime is too short\.|Initial access was not allowed\.|Simulation identity changed\.|Observer identity mismatch\.|Normal baseline request was denied\.|Baseline did not become ready within 80 minutes\.|Pre-probe access denied\.|Unexpected probe response\.)$/;
      this.state.failureReason=safe.test(message)?message:'Network or endpoint response unavailable.';
      this.state.phase = this.cancelled ? 'stopped' : 'error';
      this.state.message = this.cancelled ? 'Stopped by operator.' : 'Demo stopped at '+this.state.failureStage+': '+this.state.failureReason;
      if(!this.cancelled)console.warn('Bounded risk demo stopped:',this.state.failureStage,this.state.failureReason);
    }).finally(() => { this.running = false; });
    return this.state;
  }
  stop() { this.cancelled = true; }
  check() { if (this.cancelled) throw Error('Stopped'); }
  async execute(config) {
    validateConfig(config);
    const token = await this.json(config.issuer+'/protocol/openid-connect/token', {method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:new URLSearchParams({
        grant_type:'client_credentials', client_id:config.clientId, client_secret:config.clientSecret})});
    if (!token.access_token || token.expires_in < 5400) throw Error('Simulation token lifetime is too short.');
    const headers = {Authorization:'Bearer '+token.access_token, 'X-Zetris-Demo-Run':this.state.run};
    const normalURL = config.appOrigin+'/juice/simulation/normal';
    const normal = async () => {
      this.check();
      const response = await this.request(normalURL, {headers});
      const status = response.status;
      if (status === 200) {
        const identity = await response.json();
        if (identity.tenant !== config.tenant || identity.user !== SIM_USER || !identity.session ||
            (this.state.session && this.state.session !== identity.session)) throw Error('Simulation identity changed.');
        this.state.session = identity.session;
        this.state.beforeAllowed = true;
      } else { await response.body?.cancel(); }
      this.state.normalSent++;
      return status;
    };
    const observe = async () => {
      this.check();
      const value = await this.json(config.auditOrigin+'/api/simulation?sid='+encodeURIComponent(this.state.session), {headers});
      if (value.tenant !== config.tenant || value.user !== config.subject || value.session !== this.state.session) throw Error('Observer identity mismatch.');
      this.state.evidence = value;
      return value;
    };
    if (await normal() !== 200) throw Error('Initial access was not allowed.');
    this.state.phase = 'baseline';
    this.state.message = 'Building real normal history. A new identity usually needs about one hour; the audit service confirms readiness.';
    const warmupDeadline = this.now()+80*60000;
    let evidence;
    for (let i=0; this.now()<warmupDeadline; i++) {
      if (i%2===0) { evidence = await observe(); if (evidence.baseline_ready) break; }
      await this.sleep(12000);
      if (await normal() !== 200) throw Error('Normal baseline request was denied.');
    }
    if (!evidence?.baseline_ready) throw Error('Baseline did not become ready within 80 minutes.');
    this.state.phase = 'aligning';
    this.state.message = 'Baseline verified. Aligning the bounded probe with a fresh five-minute window.';
    const attackStart = (Math.floor(this.now()/300000)+1)*300000+3000;
    while (this.now()<attackStart) { await this.sleep(Math.min(12000,attackStart-this.now())); if (await normal() !== 200) throw Error('Pre-probe access denied.'); }
    this.state.phase = 'probing';
    this.state.message = 'Sending at most 180 synthetic fault requests at one per second. No real password guessing or exploit payloads.';
    for (let i=0; i<180; i++) {
      this.check();
      const start=this.now();
      const kind = i%4===3 ? 'latency' : i%4===1 ? 'missing' : 'auth-failure';
      const response = await this.request(`${config.appOrigin}/juice/simulation/probe/${this.state.run}/${kind}/${i}`, {
        method:kind==='auth-failure' ? 'POST' : 'GET', headers:{...headers,'X-Zetris-Simulation':'bounded-v1'}});
      const expected=kind==='auth-failure' ? 401 : kind==='missing' ? 404 : 200;
      // Denials can arrive as the window is scored; only audit evidence proves why.
      if (![expected,403].includes(response.status)) { await response.body?.cancel(); throw Error('Unexpected probe response.'); }
      await response.body?.cancel();
      this.state.probesSent++;
      await this.sleep(Math.max(0,1000-(this.now()-start)));
    }
    this.state.phase = 'verifying';
    this.state.message = 'Waiting for the closed window, grace period and collector delivery; verifying the automatic block.';
    const verifyDeadline = this.now()+9*60000;
    while (this.now()<verifyDeadline) {
      const status=await normal();
      evidence=await observe();
      this.state.afterStatus=status;
      if (status===403 && evidence.blocked && evidence.critical_block && evidence.before_allowed && evidence.after_denied) {
        this.state.success=true;
        this.state.phase='complete';
        this.state.message='Verified: normal access → CRITICAL risk decision → session block → previously allowed request denied.';
        return;
      }
      await this.sleep(15000);
    }
    this.state.phase='inconclusive';
    this.state.message='Traffic completed, but all automatic-block evidence was not present. This is not a successful blocking demonstration.';
  }
}

function simulationRoute(req,res,pathname,simulation) {
  if (!pathname.startsWith('/simulation')) return false;
  if (pathname==='/simulation' || pathname==='/simulation.js') return false;
  const json=(code,value)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(value));};
  const user=req.headers['x-current-user'];
  if (user===SIM_USER && pathname==='/simulation/normal' && req.method==='GET') {
    json(200,{tenant:req.headers['x-tenant-id'],user,session:req.headers['x-session-id']});return true;
  }
  const match=pathname.match(/^\/simulation\/probe\/[a-z0-9-]{1,40}\/(auth-failure|missing|latency)\/[0-9]{1,3}$/);
  if (match && user===SIM_USER && req.headers['x-zetris-simulation']==='bounded-v1') {
    const kind=match[1], expectedMethod=kind==='auth-failure'?'POST':'GET';
    if(req.method!==expectedMethod){json(405,{error:'Wrong simulation method'});return true;}
    if(kind==='latency')setTimeout(()=>json(200,{simulation:true}),200);
    else json(kind==='missing'?404:401,{simulation:true,kind});
    return true;
  }
  if(user!=='zetris-admin'){json(403,{error:'Operator required'});return true;}
  let config;
  try {config=simulation.config();}catch {json(503,{error:'Simulation is not activated. Its reviewed identity setup must complete first.'});return true;}
  if(req.headers['x-tenant-id']!==config.tenant){json(403,{error:'Wrong tenant'});return true;}
  if(pathname==='/simulation/status' && req.method==='GET'){json(200,{...simulation.state,running:simulation.running,tenant:config.tenant});return true;}
  if(['/simulation/run','/simulation/stop'].includes(pathname) && req.method==='POST') {
    if(req.headers.origin!==config.appOrigin || req.headers['content-type']!=='application/json') {json(403,{error:'Same-origin JSON request required'});return true;}
    if(pathname.endsWith('/stop')){simulation.stop();json(202,{status:'stopping'});return true;}
    try {json(202,simulation.start(config));}catch {json(409,{error:'A demonstration is already running'});}
    return true;
  }
  return false;
}
function validateWorkerControl(req,simulation){
  try {
    const expected=simulation.config().controlSecret;
    const supplied=req.headers['x-zetris-simulation-control']||'';
    return typeof expected==='string' && supplied.length===expected.length && timingSafeEqual(Buffer.from(supplied),Buffer.from(expected));
  }catch{return false;}
}
async function proxyControl(req,res,pathname,workerURL){
  const send=(code,value)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(value));};
  try{
    if(!/^http:\/\/risk-demo-worker(?:-t2)?:3000$/.test(workerURL))throw Error('Invalid controller target');
    const config=JSON.parse(fs.readFileSync('/run/zetris-demo-control/config.json','utf8'));
    if(req.headers['x-current-user']!=='zetris-admin'||req.headers['x-tenant-id']!==config.tenant)return send(403,{error:'Operator required'});
    if(req.method==='POST'&&(req.headers.origin!==config.appOrigin||req.headers['content-type']!=='application/json'))return send(403,{error:'Same-origin JSON request required'});
    if(!(req.method==='GET'&&pathname==='/simulation/status')&&!(req.method==='POST'&&['/simulation/run','/simulation/stop'].includes(pathname)))return send(405,{error:'Method not allowed'});
    const response=await fetch(workerURL+pathname,{method:req.method,redirect:'manual',signal:AbortSignal.timeout(10000),
      headers:{'x-current-user':'zetris-admin','x-tenant-id':config.tenant,'x-session-id':req.headers['x-session-id'],
        'x-zetris-simulation-control':config.controlSecret,'origin':config.appOrigin,'content-type':'application/json'},
      body:req.method==='POST'?'{}':undefined});
    const body=await response.json();send(response.status,body);
  }catch{send(503,{error:'Simulation worker is not ready. Its reviewed identity setup must complete first.'});}
}
module.exports={Simulation,simulationRoute,validateConfig,SIM_USER,proxyControl,validateWorkerControl};
