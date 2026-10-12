import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {runXdr} from '../../scripts/xdr-run.mjs';
import {respond} from './respond.mjs';
import {evaluateAccess} from '../../ztna/evaluate.mjs';
if(process.argv[2]!=='exfiltration'){
  console.error('Usage: npm run xdr:run -- exfiltration');
  process.exit(1);
}
const now=new Date('2026-10-13T00:00:00.000Z');
const fixture=JSON.parse(await readFile(new URL('../fixtures/exfiltration.json',import.meta.url),'utf8'));
const root=fileURLToPath(new URL('../../',import.meta.url));
const report=await runXdr({root,moduleKey:'exfiltration'});
const deny=new URL('../temporary-deny.json',import.meta.url);
const log=new URL('../alerts.log',import.meta.url);
await writeFile(deny,'[]\n');
await writeFile(log,'');
for(let i=0;i<fixture.alerts.length;i++){
  const alert=fixture.alerts[i],d=report.decisions[i];
  if(d.alertId!==alert.id)throw new Error('Official results not aligned with Wazuh fixture');
  await respond(alert,d,{now,persist:true});
}
const policies=JSON.parse(await readFile(deny,'utf8'));
const rows=(await readFile(log,'utf8')).trim().split('\n').filter(Boolean);
if(policies.length!==report.counts.block ||
  rows.length!==report.counts.block+report.counts.alert)
  throw new Error('Notification and destination-deny counts differ from official decisions');
let normalBlocked=0;
for(let i=0;i<fixture.alerts.length;i++){
  const event=fixture.alerts[i],verdict=report.decisions[i];
  const destination=event.data.dstip;
  if(!destination){
    if(verdict.action==='block')throw new Error('No destination for a blocking verdict: '+event.id);
    continue;
  }
  const actual=await evaluateAccess(destination,now.getTime());
  const normal=event.rule.level<=3&&!event.rule.mitre?.some(x=>x==='T1041'||x==='T1048');
  if(normal&&(verdict.action==='block'||actual.action==='deny'))normalBlocked++;
  if(actual.action!==(verdict.action==='block'?'deny':'allow'))
    throw new Error('ZTNA destination scope mismatch: '+event.id);
  if(verdict.action==='block'){
    const later=await evaluateAccess(destination,now.getTime()+16*60_000);
    if(later.action!=='allow')throw new Error('Expired deny still in force: '+event.id);
  }
}
if(normalBlocked)throw new Error('Normal destination blocked');
console.log(JSON.stringify({schema:report.schema,counts:report.counts,total:fixture.alerts.length,
  normalBlocked,alertsLogged:rows.length,temporaryDenyRules:policies.length}));
