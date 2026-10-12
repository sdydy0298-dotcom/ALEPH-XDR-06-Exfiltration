// Local educational ZTNA evaluator, additive destination deny gate (XDR-06).
const obj=x=>x&&typeof x==='object'&&!Array.isArray(x)?x:{};
const target=x=>typeof x==='string'?x.trim():
  String(obj(x).destination??obj(x).dstip??obj(x).destination_ip??'').trim();
export function checkAccess(destination,dynamicRules=[],at=Date.now(),basePolicy={}){
  const dest=target(destination);
  const now=at instanceof Date?at.getTime():Number(at);
  if(!Number.isFinite(now))throw new TypeError('Invalid evaluation time');
  if(!dest)return {action:'deny',reason:'대상 목적지를 확인할 수 없음'};
  const active=r=>r && (!r.expiresAt||(Number.isFinite(Date.parse(r.expiresAt))&&Date.parse(r.expiresAt)>now));
  const staticDenied=Array.isArray(basePolicy.deny)&&basePolicy.deny.some(r=>
    active(r)&&r.action!=='allow'&&
    (r.destination===dest||r.dstip===dest||(r.target===dest)));
  if(staticDenied)return {action:'deny',reason:'기존 ZTNA 목적지 거부 정책'};
  const dynamicDenied=Array.isArray(dynamicRules)&&dynamicRules.some(r=>
    active(r)&&r.action==='deny'&&r.scope==='destination'&&r.destination===dest
    &&typeof r.expiresAt==='string'&&Number.isFinite(Date.parse(r.expiresAt)));
  return dynamicDenied
    ?{action:'deny',reason:'XDR-06 외부 반출 목적지 임시 거부'}
    :{action:'allow',reason:'활성 목적지 거부 규칙 없음'};
}
