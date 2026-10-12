import {readFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const file=new URL('../fixtures/exfiltration.json',import.meta.url);
export function redact(value){
  return String(value??'').replace(/[\r\n\t]/g,' ')
    .replace(/\b(?:password|passwd|pwd|token|secret|cookie|authorization|api[_-]?key)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi,'[REDACTED]')
    .replace(/\bBearer\s+\S+/gi,'Bearer [REDACTED]')
    .replace(/\b[A-Za-z0-9_-]{48,}\b/g,'[REDACTED]').slice(0,240);
}
export function projectAlert(event){
  const d=event?.data??{};
  const ip=String(d.srcip??d.src_ip??d.source_ip??event?.srcip??'');
  const level=Number(event?.rule?.level??0);
  return {
    time:redact(event?.timestamp),source:isIP(ip)?ip:'',
    account:redact(d.srcuser??d.dstuser??d.username??event?.account),
    level:Number.isFinite(level)?level:0,
    description:redact(event?.rule?.description)
  };
}
export async function readAlerts(){
  const fixture=JSON.parse(await readFile(file,'utf8'));
  if(fixture.schema!=='aleph.xdr.fixture.v1'||fixture.moduleKey!=='exfiltration'||
    !Array.isArray(fixture.alerts))throw new Error('Official exfiltration fixture schema mismatch');
  return fixture.alerts.map(projectAlert);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)
  for(const line of await readAlerts())console.log(JSON.stringify(line));
