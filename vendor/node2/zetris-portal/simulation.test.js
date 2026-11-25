const {test}=require('node:test');
const assert=require('node:assert/strict');
const {Simulation,validateConfig,SIM_USER,validateWorkerControl}=require('./simulation');
const {createServer}=require('./server');
const config={tenant:'ztna',subject:'own-user',clientId:'zetris-risk-simulator',clientSecret:'test-only',operator:'zetris-admin',
  appOrigin:'https://app.ztna.sc.deeptrustxai.com',auditOrigin:'https://audit.ztna.sc.deeptrustxai.com',issuer:'https://auth.ztna.sc.deeptrustxai.com/realms/ztna'};
test('worker sends bounded attributed traffic and requires all independent proof',async()=>{
  for(const prove of [true,false]){
    let clock=3000000,probes=0,normal=0,observations=0;
    const simulator=new Simulation({now:()=>clock,sleep:async ms=>{clock+=ms},fetch:async(url,options)=>{
      if(url.endsWith('/token'))return Response.json({access_token:'private-test-token',expires_in:7200});
      assert.equal(options.headers.Authorization,'Bearer private-test-token');
      assert.match(options.headers['X-Zetris-Demo-Run'],/^[0-9a-f-]{36}$/);
      if(url.endsWith('/normal')){normal++;return probes===180?new Response('',{status:403}):Response.json({tenant:'ztna',user:SIM_USER,session:'own-session'});}
      if(url.includes('/api/simulation?')){observations++;return Response.json({tenant:'ztna',user:'own-user',session:'own-session',baseline_ready:observations>2,blocked:probes===180,critical_block:prove&&probes===180,before_allowed:true,after_denied:probes===180});}
      probes++;const kind=url.split('/').at(-2);
      assert.ok(url.startsWith(config.appOrigin+'/juice/simulation/probe/'));
      assert.equal(options.method,kind==='auth-failure'?'POST':'GET');
      return new Response('{}',{status:kind==='auth-failure'?401:kind==='missing'?404:200});
    }});
    simulator.start(config);await simulator.completion;
    assert.equal(probes,180);assert.ok(normal>2);
    assert.equal(simulator.state.success,prove);
    assert.equal(simulator.state.phase,prove?'complete':'inconclusive');
    assert.ok(!JSON.stringify(simulator.state).includes('private-test-token'));
  }
});
test('simulation targets cannot be redirected to another host or tenant',()=>{
  for(const value of ['http://app.ztna.sc.deeptrustxai.com','https://evil.example','https://app.ztna.sc.deeptrustxai.com/','https://tenant2-app.ztna.sc.deeptrustxai.com']){
    assert.throws(()=>validateConfig({...config,appOrigin:value}));
  }
});
test('private worker rejects absent or incorrect controller credentials',()=>{
  const simulation={config:()=>({controlSecret:'a'.repeat(64)})};
  assert.equal(validateWorkerControl({headers:{}},simulation),false);
  assert.equal(validateWorkerControl({headers:{'x-zetris-simulation-control':'b'.repeat(64)}},simulation),false);
  assert.equal(validateWorkerControl({headers:{'x-zetris-simulation-control':'a'.repeat(64)}},simulation),true);
});
test('faults require the signed simulation identity and cannot start a runner',async t=>{
  const server=createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  const base=`http://127.0.0.1:${server.address().port}`;
  const identity={'x-tenant-id':'ztna','x-current-user':SIM_USER,'x-session-id':'own-run','x-zetris-simulation':'bounded-v1'};
  assert.equal((await fetch(base+'/simulation/normal',{headers:identity})).status,200);
  assert.equal((await fetch(base+'/simulation/probe/test-run/auth-failure/1',{method:'POST',headers:identity})).status,401);
  assert.equal((await fetch(base+'/simulation/probe/test-run/missing/1',{headers:identity})).status,404);
  assert.equal((await fetch(base+'/simulation/run',{method:'POST',headers:identity})).status,403);
  assert.equal((await fetch(base+'/simulation/normal',{headers:{...identity,'x-current-user':'other-user'}})).status,403);
  assert.equal((await fetch(base+'/simulation')).status,403);
  const page=await fetch(base+'/simulation',{headers:{...identity,'x-current-user':'zetris-admin'}});
  assert.equal(page.status,200);assert.ok(page.headers.get('content-security-policy').includes("connect-src 'self'"));
  assert.ok(!(await page.text()).includes('own-run'));
});
test('operator control requires exact origin and JSON and never accepts user-supplied targets',async t=>{
  let starts=0,stops=0;
  const simulation={config:()=>config,state:{phase:'idle'},running:false,start(value){assert.equal(value,config);starts++;return this.state},stop(){stops++}};
  const server=createServer({simulation});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  const base=`http://127.0.0.1:${server.address().port}`;
  const identity={'x-tenant-id':'ztna','x-current-user':'zetris-admin','x-session-id':'operator-session'};
  for(const extra of [{},{origin:'https://evil.example','content-type':'application/json'},{origin:config.appOrigin,'content-type':'text/plain'}]){
    assert.equal((await fetch(base+'/simulation/run',{method:'POST',headers:{...identity,...extra},body:'{}'})).status,403);
  }
  assert.equal(starts,0);
  assert.equal((await fetch(base+'/simulation/run',{method:'POST',headers:{...identity,origin:config.appOrigin,'content-type':'application/json'},body:JSON.stringify({target:'https://evil.example',rate:999})})).status,202);
  assert.equal(starts,1);
  assert.equal((await fetch(base+'/simulation/stop',{method:'POST',headers:{...identity,origin:config.appOrigin,'content-type':'application/json'},body:'{}'})).status,202);
  assert.equal(stops,1);
});
