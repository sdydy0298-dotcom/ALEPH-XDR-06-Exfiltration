import {readFile,writeFile,appendFile,mkdir} from 'node:fs/promises';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {isIP} from 'node:net';
import {decide} from './decide.mjs';
import {checkAccess} from '../../ztna/check.mjs';
const temporary=new URL('../temporary-deny.json',import.meta.url);
const notifications=new URL('../alerts.log',import.meta.url);
const safeId=value=>/^[A-Za-z0-9_.:-]{1,96}$/.test(String(value??''))?String(value):null;
const safeDestination=value=>typeof value==='string'&&isIP(value.trim())?value.trim():null;
async function readRules(){
  try{
    const value=JSON.parse(await readFile(temporary,'utf8'));
    if(!Array.isArray(value))throw new Error('Malformed temporary deny rules');
    return value;
  }catch(e){if(e.code==='ENOENT')return [];throw e;}
}
export async function respond(event,verdict,{now=new Date(),persist=true}={}){
  if(!verdict || !['block','alert','record'].includes(verdict.action) ||
    !Number.isFinite(verdict.confidence)||verdict.confidence<0||verdict.confidence>1)
    throw new TypeError('Invalid classification result');
  if(!(now instanceof Date)||Number.isNaN(now.getTime()))throw new TypeError('Invalid clock');
  const d=event?.data??{};
  const evidence=safeId(event?.id??event?.alertId);
  const destination=safeDestination(d.dstip??d.dst_ip??d.destination_ip??d.dest_ip??event?.dstip);
  const verified=decide(event);
  const previous=(persist?await readRules():[]).filter(x=>
    x?.action==='deny'&&typeof x.expiresAt==='string'&&
    Number.isFinite(Date.parse(x.expiresAt))&&Date.parse(x.expiresAt)>now.getTime());
  // Never trust a forged caller verdict. A benign upload can never become DENY.
  if(verdict.action==='block' && verdict.confidence>=.85 &&
    verified.action==='block'&&evidence&&destination){
    const rule={id:'xdr06-'+evidence,action:'deny',scope:'destination',
      destination,alertId:evidence,reason:verified.reason,
      createdAt:now.toISOString(),expiresAt:new Date(now.getTime()+900_000).toISOString()};
    if(!previous.some(x=>x.id===rule.id))previous.push(rule);
  }
  const notification={alertId:evidence??'unknown',action:verified.action,
    confidence:verified.confidence,reason:verified.reason,at:now.toISOString()};
  if(persist){
    await mkdir(dirname(fileURLToPath(temporary)),{recursive:true});
    await writeFile(temporary,JSON.stringify(previous,null,2)+'\n');
    if(verified.action!=='record')
      await appendFile(notifications,JSON.stringify(notification)+'\n');
  }
  return {notification:verified.action==='record'?null:notification,
    rules:previous,access:destination?checkAccess(destination,previous,now):
      {action:'allow',reason:'목적지가 불명확해 임시 차단 규칙을 추가하지 않음'}};
}
