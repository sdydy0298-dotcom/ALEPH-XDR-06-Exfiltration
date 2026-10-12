import {readFile,writeFile,copyFile,mkdir} from 'node:fs/promises';
import {checkAccess} from '../ztna/check.mjs';
const base=new URL('../',import.meta.url),atPath=path=>new URL(path,base);
const original=JSON.parse(await readFile(atPath('xdr/fixtures/exfiltration.json'),'utf8'));
const result=JSON.parse(await readFile(atPath('xdr/exfiltration/result.json'),'utf8'));
const dynamic=JSON.parse(await readFile(atPath('xdr/temporary-deny.json'),'utf8'));
const baseline=JSON.parse(await readFile(atPath('ztna/rules.json'),'utf8'));
const notifications=(await readFile(atPath('xdr/alerts.log'),'utf8')).trim().split('\n').filter(Boolean);
if(original.schema!=='aleph.xdr.fixture.v1'||original.moduleKey!=='exfiltration'||original.alerts?.length!==30)
  throw new Error('Official fixture mismatch');
if(result.schema!=='aleph.xdr.result.v1'||result.moduleKey!=='exfiltration'||result.decisions?.length!==30)
  throw new Error('Official result mismatch');
if(!Array.isArray(dynamic)||dynamic.length!==result.counts.block||
  notifications.length!==result.counts.block+result.counts.alert)
  throw new Error('Dynamic policies / log count mismatch');
const samples=original.alerts.map(a=>({
 id:a.id,timestamp:a.timestamp,
 rule:{level:a.rule.level,mitre:a.rule.mitre,description:a.rule.description},
 data:{srcip:a.data.srcip,srcuser:a.data.srcuser,dstip:a.data.dstip??null,
   bytes:a.data.bytes??'0',files:a.data.files??null,count:a.data.count??null}
}));
const rows=result.decisions.map((v,i)=>{
 const a=samples[i];if(a.id!==v.alertId)throw new Error('Event-order mismatch');
 return {
   alertId:v.alertId,action:v.action,confidence:v.confidence,reason:v.reason,
   description:a.rule.description,source:a.data.srcip,destination:a.data.dstip,
   bytes:a.data.bytes,fileCount:a.data.files,repeatCount:a.data.count,level:a.rule.level,
   normal:!a.rule.mitre.some(x=>x==='T1041'||x==='T1048')&&a.rule.level<=3
 };
});
const now=Date.parse('2026-10-13T00:00:00.000Z');
let falseBlocks=0;
for(const row of rows){
 if(row.normal&&row.action==='block')falseBlocks++;
 if(!row.destination){
   if(row.action==='block')throw new Error('Blocking without a known destination');
   continue;
 }
 const checked=checkAccess(row.destination,dynamic,now,baseline);
 if(row.normal&&checked.action==='deny')falseBlocks++;
 if(checked.action!==(row.action==='block'?'deny':'allow'))
   throw new Error('Wrong ZTNA classification: '+row.alertId);
}
if(falseBlocks)throw new Error('Normal destination incorrectly denied');
const report={
 schema:'aleph.xdr.result.v1',moduleKey:'exfiltration',generatedAt:'2026-10-13T00:00:00.000Z',
 fixtureCount:30,counts:result.counts,normalBlocked:falseBlocks,
 temporaryDenyRules:dynamic.map(x=>({id:x.id,destination:x.destination,
   alertId:x.alertId,expiresAt:x.expiresAt})),
 results:rows
};
await mkdir(atPath('public/'),{recursive:true});
await writeFile(atPath('public/report.json'),JSON.stringify(report,null,2)+'\n');
await writeFile(atPath('public/samples.json'),JSON.stringify({alerts:samples},null,2)+'\n');
for(const [from,to] of [
 ['index.html','public/index.html'],['app.js','public/app.js'],
 ['styles.css','public/styles.css'],
 ['xdr/exfiltration/decide.mjs','public/decide.mjs']
])await copyFile(atPath(from),atPath(to));
console.log(JSON.stringify({ready:true,counts:result.counts,
 normalBlocked:falseBlocks,destinationRules:dynamic.length}));
