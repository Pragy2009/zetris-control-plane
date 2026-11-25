'use strict';
const el=id=>document.getElementById(id);
const auditHost=location.hostname==='tenant2-app.ztna.sc.deeptrustxai.com'?'tenant2-audit.ztna.sc.deeptrustxai.com':'audit.ztna.sc.deeptrustxai.com';
el('audit').href='https://'+auditHost+'/';
async function call(path,method='GET'){
  const response=await fetch('/juice/simulation/'+path,{method,credentials:'same-origin',cache:'no-store',headers:method==='POST'?{'Content-Type':'application/json'}:{},body:method==='POST'?'{}':undefined});
  if(!response.ok){let message='Request failed: HTTP '+response.status;try{message=(await response.json()).error||message}catch{}throw Error(message)}
  return response.json();
}
async function refresh(){try{
  const s=await call('status'),e=s.evidence||{};
  el('message').textContent=s.message||'';el('phase').textContent=s.phase;
  el('counts').textContent=(s.normalSent||0)+' / '+(s.probesSent||0);
  el('baseline').textContent=e.baseline_weight===undefined?'Waiting for audit verification':e.baseline_weight.toFixed(2)+' / '+e.required_weight;
  el('session').textContent=s.session||'—';el('risk').textContent=(e.decision?.risk_level||e.risk||'Not scored yet')+' decision / '+(e.score??'—')+' current trust';
  el('result').textContent=s.success?'Automatic blocking verified':s.running?'Demonstration in progress':s.phase==='idle'?'Not started':'No verified success';
  el('result').className=s.success?'good':'';
  el('proof').textContent='Earlier access: '+Boolean(e.before_allowed)+' · CRITICAL block decision: '+Boolean(e.critical_block)+' · Block entry: '+Boolean(e.blocked)+' · Later denial: '+Boolean(e.after_denied);
  el('evidence').textContent=JSON.stringify(e,null,2);el('start').disabled=s.running;el('stop').disabled=!s.running;
}catch(error){el('message').textContent=error.message;el('start').disabled=true;el('stop').disabled=true;}}
el('start').onclick=async()=>{el('start').disabled=true;try{await call('run','POST');await refresh()}catch(e){el('message').textContent=e.message;el('start').disabled=false}};
el('stop').onclick=async()=>{try{await call('stop','POST');await refresh()}catch(e){el('message').textContent=e.message}};
refresh();setInterval(refresh,10000);
