// ALEPH XDR-06 / Exfiltration / MITRE ATT&CK T1041 + T1048
// Self-contained judge contract: no imports, filesystem, network, external packages, or clock.
const PATTERNS=Object.freeze({
  unknown:'T1048-Unknown-Destination-Large-Transfer',
  repeated:'T1041-Repeated-Large-C2-Transfer',
  offhours:'T1048-Off-Hours-Archive-Transfer',
  unusual:'T1048-Unusual-Port-Bulk-Export',
  ambiguous:'T1041-T1048-Ambiguous-Transfer',
  normal:'T1041-T1048-Routine-Transfer'
});
const obj=x=>x&&typeof x==='object'&&!Array.isArray(x)?x:{};
const word=x=>typeof x==='string'?x:'';
const first=(...v)=>v.find(x=>x!==undefined&&x!==null&&x!=='')??null;
function quantity(value) {
  if(typeof value==='number')return Number.isFinite(value)&&value>=0&&value<=Number.MAX_SAFE_INTEGER?value:null;
  if(typeof value==='string'&&/^\s*\d+(?:\.\d+)?\s*$/.test(value)){
    const n=Number(value);return Number.isSafeInteger(n)&&n>=0?n:null;
  }
  return null;
}
function validIp(value){
  if(typeof value!=='string')return false;
  const s=value.trim();
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(s))
    return s.split('.').every(p=>Number(p)>=0&&Number(p)<=255);
  return s.includes(':')&&/^[0-9a-f:]{2,45}$/i.test(s);
}
function signals(alert){
  const a=obj(alert),d=obj(a.data),rule=obj(a.rule);
  const event=obj(d.event),network=obj(d.network),src=obj(d.src);
  const description=[rule.description,a.description,d.description,event.description,d.message]
    .filter(x=>typeof x==='string').join(' ').toLowerCase();
  const dest=first(d.dstip,d.dst_ip,d.destination_ip,d.dest_ip,d.destinationIp,
    network.dstip,network.destination,a.dstip,obj(d.destination).ip);
  const bytes=quantity(first(d.bytes,d.bytes_sent,d.sent_bytes,d.transfer_bytes,
    network.bytes,network.bytes_sent,d.size))??0;
  const files=quantity(first(d.files,d.file_count,d.fileCount,d.file_total))??0;
  const attempts=quantity(first(d.count,d.frequency,d.attemptCount,d.transfer_count))??0;
  const level=quantity(first(rule.level,a.level,d.level))??0;
  const tags=Array.isArray(rule.mitre)?rule.mitre.map(t=>typeof t==='string'?t:word(obj(t).id)):[];
  const tagged=tags.includes('T1041')||tags.includes('T1048');
  const unknown=/처음\s*보는|낯선|평소(?:에)?\s*(?:쓰지|않)|다른\s*주소|평소와\s*다른\s*주소|미승인|외부(?:의)?\s*낯선|unknown\s+dest|new\s+dest|unrecognized\s+dest|unapproved\s+dest/.test(description)
    || d.firstSeen===true || d.destinationKnown===false || d.approvedDestination===false;
  const offhours=/수업\s*시간\s*밖|업무\s*시간\s*밖|퇴근\s*뒤|야간|근무\s*시간\s*밖|off.hours|after.hours|outside\s+(?:business|working)\s+hours/.test(description);
  const archive=/압축|묶음|zip|tar|archive|bundle/.test(description)
    || /\.(?:zip|7z|rar|tar|gz|tgz)$/i.test(word(d.filename));
  const repeated=/반복|연속|여러\s*번|[0-9]+\s*번|수차례|repeated|multiple\s+transfers?/.test(description)
    || attempts>=5;
  const unusualPort=/평소(?:에)?\s*쓰지\s*않던\s*포트|낯선\s*포트|비표준\s*포트|unusual\s+port|non.standard\s+port/.test(description)
    || d.unusualPort===true;
  const entire=/자료실\s*전체|전체\s*자료|모든\s*파일|전체\s*복사|entire\s+(?:library|folder|directory)|all\s+files/.test(description);
  const command=/명령\s*통로|명령\s*채널|c2\s*channel|command.and.control|c&c\s*channel/.test(description);
  const noTransfer=/전송(?:은|이)?\s*(?:아직\s*)?없|전송\s*실패|전송\s*안함|전송\s*취소|전송하지\s*않|no\s+transfer|not\s+transferred|failed\s+transfer/.test(description);
  const routine=/수업\s*자료\s*주소|평소\s*목적지|정상\s*동기화|메모.{0,12}(?:읽|저장)|공지(?:를)?\s*읽|검색\s*결과|화면\s*새로고침|로그아웃|세션\s*확인|일반\s*화면|정상\s*백업/.test(description);
  return {tagged,level,validDestination:validIp(dest),bytes,files,attempts,unknown,
    offhours,archive,repeated,unusualPort,entire,command,noTransfer,routine};
}
export function decide(alert){
  const s=signals(alert);
  const make=(confidence,reason)=>({
    action:confidence>=.85?'block':confidence>=.5?'alert':'record',
    confidence,reason
  });
  if(!s.tagged && s.level<=3)return make(.06,PATTERNS.normal);
  if(s.tagged && s.level<=3 && s.routine)return make(.07,PATTERNS.normal);
  // A prepared archive, failed/zero-byte transfer, or missing destination
  // must never create a destination-blocking rule.
  const strong=s.tagged && s.level>=10 && s.validDestination &&
    s.bytes>=50_000_000 && !s.noTransfer;
  if(strong){
    if(s.entire&&s.files>=30)return make(.99,PATTERNS.unusual);
    if(s.unusualPort&&(s.files>=20||s.repeated))return make(.98,PATTERNS.unusual);
    if(s.offhours&&s.archive)return make(.98,PATTERNS.offhours);
    if(s.command&&s.repeated)return make(.97,PATTERNS.repeated);
    if(s.repeated&&(s.attempts>=5 || s.offhours))return make(.97,PATTERNS.repeated);
    if(s.unknown)return make(s.archive?.98:.96,s.archive?PATTERNS.offhours:PATTERNS.unknown);
    if(s.entire||s.unusualPort||s.offhours)return make(.94,PATTERNS.unusual);
  }
  if(s.tagged && s.level>=5)return make(.62,PATTERNS.ambiguous);
  if(s.level>=7 && (s.unknown||s.offhours||s.unusualPort||s.repeated||s.bytes>=50_000_000))
    return make(.53,PATTERNS.ambiguous);
  return make(.06,PATTERNS.normal);
}
