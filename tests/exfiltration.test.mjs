import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {decide} from '../xdr/exfiltration/decide.mjs';
import {readAlerts,projectAlert} from '../xdr/exfiltration/read-alerts.mjs';
import {respond} from '../xdr/exfiltration/respond.mjs';
import {checkAccess} from '../ztna/check.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';

const json=async path=>JSON.parse(await readFile(new URL('../'+path,import.meta.url),'utf8'));
const fixture=await json('xdr/fixtures/exfiltration.json');
const result=await json('xdr/exfiltration/result.json');
const now=new Date('2026-10-13T00:00:00.000Z');
const mk=(description,bytes=240_000_000,level=12,mitre=['T1048'],more={})=>({
 id:'test-01',timestamp:now.toISOString(),
 rule:{level,mitre,description},
 data:{srcip:'192.0.2.130',srcuser:'lab-tester',dstip:'198.51.100.130',bytes:String(bytes),files:'40',...more}
});

test('upstream unmodified educational Wazuh fixture uses 30 unique alerts',()=>{
 assert.equal(fixture.schema,'aleph.xdr.fixture.v1');
 assert.equal(fixture.moduleKey,'exfiltration');
 assert.equal(fixture.alerts.length,30);
 assert.equal(new Set(fixture.alerts.map(x=>x.id)).size,30);
 assert.ok(fixture.alerts.every(x=>x.agent?.name==='choi-bujang-pc'));
});

test('reader reports exactly one masked five-field summary per alert',async()=>{
 const out=await readAlerts();
 assert.equal(out.length,30);
 assert.ok(out.every(x=>Object.keys(x).sort().join(',')==='account,description,level,source,time'));
 const cli=spawnSync(process.execPath,['xdr/exfiltration/read-alerts.mjs'],{encoding:'utf8'});
 assert.equal(cli.status,0,cli.stderr);
 assert.equal(cli.stdout.trim().split('\n').length,30);
 const hidden=projectAlert({
  rule:{level:13,description:'password=example123 token=hidden-string'},
  data:{srcip:'192.0.2.3',srcuser:'Bearer private-session'}
 });
 assert.doesNotMatch(JSON.stringify(hidden),/example123|hidden-string|private-session/);
});

test('independent judge contains no imports, files, network, clock or external dependencies',async()=>{
 const code=await readFile(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),'utf8');
 assert.match(code,/export function decide\(alert\)/);
 assert.match(code,/const PATTERNS/);
 assert.doesNotMatch(code,/^\s*import(?:\s|[{*"'(])/m);
 assert.doesNotMatch(code,/\b(?:fetch|require|readFile|writeFile|eval|Date\.now|new\s+Date)\s*\(/);
 assert.deepEqual(decide({}),{action:'record',confidence:.06,
   reason:'T1041-T1048-Routine-Transfer'});
});

test('T1041 and T1048 pattern reasons match stand-alone module constant names',async()=>{
 const patterns=await json('xdr/exfiltration/patterns.json');
 const code=await readFile(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),'utf8');
 assert.ok(patterns.length>=4);
 for(const p of patterns){
  assert.ok(p.name && p.condition && p.evidence);
  assert.match(p.evidence,/T1041|T1048/);
  assert.doesNotMatch(p.evidence,/[\r\n]/);
  assert.ok(code.includes(p.name),p.name);
 }
 assert.ok(patterns.some(x=>x.evidence.includes('T1041')));
 assert.ok(patterns.some(x=>x.evidence.includes('T1048')));
});

test('official result schema and decisions match runtime judge exactly, 10/10/10',()=>{
 assert.equal(result.schema,'aleph.xdr.result.v1');
 assert.equal(result.moduleKey,'exfiltration');
 assert.equal(result.decisions.length,30);
 const totals={block:0,alert:0,record:0};
 fixture.alerts.forEach((event,i)=>{
   const v=decide(event);
   assert.deepEqual(result.decisions[i],{alertId:event.id,...v},event.id);
   assert.ok(Number.isFinite(v.confidence)&&v.confidence>=0&&v.confidence<=1);
   assert.equal(v.action,v.confidence>=.85?'block':v.confidence>=.5?'alert':'record');
   assert.ok(v.reason && !/[\r\n]/.test(v.reason));
   totals[v.action]++;
 });
 assert.deepEqual(totals,{block:10,alert:10,record:10});
 assert.deepEqual(result.counts,totals);
});

for(const [i,event] of fixture.alerts.entries()){
 const expected=i<10?'block':i<20?'alert':'record';
 test('official '+event.id+' should '+expected,()=>
   assert.equal(decide(event).action,expected,JSON.stringify(decide(event))));
}

test('10 deny rules block destinations only, preserving unrelated source and account',async()=>{
 const rules=await json('xdr/temporary-deny.json');
 assert.equal(rules.length,10);
 assert.equal(new Set(rules.map(x=>x.alertId)).size,10);
 assert.equal(new Set(rules.map(x=>x.destination)).size,8);
 for(const p of rules){
  assert.equal(p.scope,'destination');
  assert.equal(p.action,'deny');
  assert.ok(p.destination&&p.alertId&&p.reason);
  assert.equal(Object.hasOwn(p,'srcip'),false);
  assert.equal(Object.hasOwn(p,'account'),false);
  assert.equal(Date.parse(p.expiresAt)-Date.parse(p.createdAt),900_000);
  assert.equal((await evaluateAccess(p.destination,now)).action,'deny');
  assert.equal((await evaluateAccess(p.destination,now.getTime()+16*60_000)).action,'allow');
 }
 assert.equal(checkAccess('192.0.2.89',rules,now).action,'allow');
});

test('same destination receives distinct evidence IDs without duplicate user blocking',async()=>{
 const a=fixture.alerts.find(x=>x.id==='ex-01'),b=fixture.alerts.find(x=>x.id==='ex-03');
 assert.equal(a.data.dstip,b.data.dstip);
 assert.notEqual(a.data.srcip,b.data.srcip);
 assert.equal((await evaluateAccess(a.data.dstip,now)).action,'deny');
 assert.equal((await evaluateAccess('192.0.2.10',now)).action,'allow');
 const normal=fixture.alerts.find(x=>x.id==='ex-21');
 assert.equal((await evaluateAccess(normal.data.dstip,now)).action,'allow');
});

test('all ambiguous and normal destinations pass local ZTNA, including low-level tagged logs',async()=>{
 for(const event of fixture.alerts){
  const verdict=decide(event);
  if(!event.data.dstip){
    assert.notEqual(verdict.action,'block',event.id);
    continue;
  }
  const access=await evaluateAccess(event.data.dstip,now);
  assert.equal(access.action,verdict.action==='block'?'deny':'allow',event.id);
 }
 assert.equal(decide(fixture.alerts.find(x=>x.id==='ex-23')).action,'record');
});

test('existing baseline destination block is honored without editing original rules',async()=>{
 const base=await json('ztna/rules.json');
 assert.ok(Array.isArray(base.allow)&&Array.isArray(base.deny));
 assert.equal(checkAccess('198.51.100.200',[],now,{deny:[
  {action:'deny',destination:'198.51.100.200'}
 ]}).action,'deny');
 assert.equal(checkAccess('198.51.100.201',[],now,{deny:[
  {action:'deny',destination:'198.51.100.200'}
 ]}).action,'allow');
});

test('notification log records exactly BLOCK and ALERT without data payload secrets',async()=>{
 const text=await readFile(new URL('../xdr/alerts.log',import.meta.url),'utf8');
 const logs=text.trim().split('\n').map(x=>JSON.parse(x));
 assert.equal(logs.length,20);
 for(const item of logs){
  assert.ok(item.action==='block'||item.action==='alert');
  assert.ok(item.alertId && item.at && item.reason);
  assert.equal(Object.hasOwn(item,'password'),false);
  assert.equal(Object.hasOwn(item,'token'),false);
  assert.equal(Object.hasOwn(item,'payload'),false);
  assert.equal(Object.hasOwn(item,'fileName'),false);
 }
});

test('forged block decision cannot deny an ordinary or uncertain destination',async()=>{
 for(const id of ['ex-11','ex-14','ex-21','ex-23']){
  const event=fixture.alerts.find(x=>x.id===id);
  const result=await respond(event,{action:'block',confidence:.99,reason:'forged'},
    {now,persist:false});
  assert.equal(result.rules.length,0,id);
  assert.equal(result.access.action,'allow',id);
 }
});

test('invalid confidence, time and missing destination cannot produce an active rule',async()=>{
 const attack=fixture.alerts[0];
 await assert.rejects(()=>respond(attack,{action:'block',confidence:NaN,reason:'bad'},
   {now,persist:false}),TypeError);
 await assert.rejects(()=>respond(attack,decide(attack),
   {now:new Date('invalid'),persist:false}),TypeError);
 const missing=mk('처음 보는 목적지로 대량 자료를 전송했습니다.',190_000_000,12,['T1048'],
   {dstip:''});
 const attempted=await respond(missing,{action:'block',confidence:.99,reason:'forged'},
   {now,persist:false});
 assert.equal(attempted.rules.length,0);
});

const edgeCases=[
 ['huge transfer to new destination',mk('처음 보는 목적지로 200건 자료 전송',240_000_000), 'block'],
 ['off-hours archive',mk('업무 시간 밖에 압축 파일이 나갔습니다.',170_000_000), 'block'],
 ['repeated bulk upload',mk('같은 목적지로 대용량 전송 8번 반복',95_000_000,11,['T1041'],{count:'8'}), 'block'],
 ['unusual port with 60 files',mk('평소에 쓰지 않던 포트로 파일 60건이 연속 전송됐습니다.',120_000_000,12,['T1048'],{files:'60'}), 'block'],
 ['whole directory copied',mk('자료실 전체가 외부 목적지로 복사됐습니다.',320_000_000,12,['T1041'],{files:'400'}), 'block'],
 ['command channel repeated',mk('명령 통로로 큰 파일이 9번 반복 전송됐습니다.',80_000_000,12,['T1041'],{count:'9'}), 'block'],
 ['short but unknown bulk data',mk('처음 보는 목적지로 한 번에 대용량 자료 전송',90_000_000), 'block'],
 ['high severity but low volume',mk('처음 보는 목적지에 작은 파일 2건 전송',400_000), 'alert'],
 ['medium file new destination',mk('평소와 다른 주소로 파일 1건이 나갔습니다.',8_000_000,6), 'alert'],
 ['large transfer to known approved endpoint',mk('평소 목적지로 일반 백업이 완료되었습니다.',350_000_000), 'alert'],
 ['high volume with unknown untagged telemetry',mk('처음 보는 목적지로 대용량 전송이 발견됐습니다.',200_000_000,12,[]), 'alert'],
 ['no MITRE but suspicious destination',mk('처음 보는 목적지로 큰 파일이 나갔습니다.',120_000_000,9,[]), 'alert'],
 ['archive prepared but not sent',mk('수업 시간 밖에 압축 파일을 만들었습니다. 외부 전송은 아직 없습니다.',180_000_000), 'alert'],
 ['failed transfer zero bytes',mk('처음 보는 목적지로 전송 실패 1건',0,9), 'alert'],
 ['unknown destination missing',mk('처음 보는 목적지로 대용량 전송',200_000_000,12,['T1048'],{dstip:''}), 'alert'],
 ['invalid destination address',mk('처음 보는 목적지로 대용량 전송',200_000_000,12,['T1048'],{dstip:'999.999.999.999'}), 'alert'],
 ['unknown destination but low severity',mk('처음 보는 목적지로 대용량 전송',200_000_000,7), 'alert'],
 ['small off-hours transfer',mk('업무 시간 밖에 작은 압축 파일 하나를 보냈습니다.',2_000_000,7), 'alert'],
 ['routine low-level synced files',mk('수업 자료 주소로 작은 동기화가 끝났습니다.',20_000,3), 'record'],
 ['routine note read',mk('내 메모를 읽었습니다.',2400,3,[]), 'record'],
 ['log out not exfiltration',mk('로그아웃했습니다.',300,2,[]), 'record'],
 ['ordinary page refresh',mk('화면 새로고침입니다.',900,2,[]), 'record'],
 ['no data at all',{},'record']
];
for(const [name,event,expected] of edgeCases)
  test('classifier '+name,()=>assert.equal(decide(event).action,expected,
    JSON.stringify(decide(event))));

test('website labels and source link never inherit XDR-05 template branding',async()=>{
 const source=await readFile(new URL('../index.html',import.meta.url),'utf8');
 const deployed=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../public/app.js',import.meta.url),'utf8');
 const result=await json('public/report.json');
 const samples=await json('public/samples.json');
 assert.equal(source,deployed);
 assert.match(deployed,/ALEPH XDR-06/);
 assert.match(deployed,/XDR<span class="slash">\/<\/span>06/);
 assert.equal((deployed.match(/ALEPH-XDR-06-Exfiltration/g)||[]).length,2);
 assert.doesNotMatch(deployed,/ALEPH-XDR-05|XDR<span class="slash">\/<\/span>05|T1068|T1078|pv-01/);
 assert.match(deployed,/<th>목적지 IP<\/th>/);
 assert.match(js,/import \{decide\} from '.\/decide.mjs'/);
 assert.match(js,/item.destination===destination/);
 assert.equal(result.fixtureCount,30);
 assert.equal(result.normalBlocked,0);
 assert.deepEqual(result.counts,{block:10,alert:10,record:10});
 assert.equal(samples.alerts.length,30);
});
