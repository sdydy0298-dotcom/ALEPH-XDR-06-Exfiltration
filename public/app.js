import {decide} from './decide.mjs';

const $=id=>document.getElementById(id);
const view={
  body:$('events-body'),search:$('search'),shown:$('shown'),
  desc:$('d-description'),source:$('d-ip'),destination:$('d-dest'),
  level:$('d-level'),volume:$('d-volume'),id:$('d-id'),
  badge:$('d-badge'),explain:$('d-explain'),confidence:$('d-confidence'),
  bar:$('d-bar'),pattern:$('d-pattern'),access:$('d-access'),
  status:$('replay-status')
};
const explanation={
  block:'실제 대규모 전송과 강한 유출 신호가 동시에 확인되어 외부 목적지의 임시 차단 후보입니다.',
  alert:'단일·소량·실패 전송 등 의심은 있지만 차단하기에는 근거가 부족해 알림만 남깁니다.',
  record:'일반 문서 조회나 정상 동기화는 차단하거나 추가 경보로 올리지 않고 기록합니다.'
};
const actionNames={block:'BLOCK',alert:'ALERT',record:'RECORD'};
let samples=[],report=null,filter='all',selected='ex-01';
function setText(element,value){if(element)element.textContent=String(value??'–');}
function size(value){
  const n=Number(value);
  if(!Number.isFinite(n)||n<0)return '–';
  return n>=1_000_000?(n/1_000_000).toLocaleString('ko-KR',{maximumFractionDigits:1})+' MB':
    (n/1000).toLocaleString('ko-KR',{maximumFractionDigits:1})+' KB';
}
function policy(destination){
  if(!destination)return 'ALLOW';
  const at=Date.parse(report.generatedAt);
  return report.temporaryDenyRules.some(item=>
    item.destination===destination && Date.parse(item.expiresAt)>at)?'DENY':'ALLOW';
}
function choose(id,replayed=false){
  const event=samples.find(x=>x.id===id);
  if(!event)return;
  selected=id;
  const decision=decide(event);
  setText(view.id,id);
  setText(view.desc,event.rule.description);
  setText(view.source,event.data.srcip);
  setText(view.destination,event.data.dstip||'전송 목적지 없음');
  setText(view.level,event.rule.level);
  const pieces=[size(event.data.bytes),'파일 '+(event.data.files??'미집계')+'건'];
  if(event.data.count!==null&&event.data.count!==undefined)pieces.push('반복 '+event.data.count+'회');
  setText(view.volume,pieces.join(' · '));
  setText(view.badge,actionNames[decision.action]);
  view.badge.className='decision-badge is-'+decision.action;
  setText(view.explain,explanation[decision.action]);
  setText(view.confidence,Math.round(decision.confidence*100)+'%');
  view.bar.style.width=(decision.confidence*100)+'%';
  setText(view.pattern,decision.reason);
  const ztna=policy(event.data.dstip);
  setText(view.access,ztna);
  view.access.className=ztna==='DENY'?'denied':'allowed';
  for(const item of document.querySelectorAll('[data-case]')){
    const active=item.dataset.case===id;
    item.classList.toggle('active',active);
    item.setAttribute('aria-pressed',String(active));
  }
  setText(view.status,replayed?
    '✓ 공식 단독 판정기를 브라우저에서 다시 실행했습니다. 실제 네트워크는 차단하지 않았습니다.':'');
  drawTable();
}
function cell(row,value,cls){
  const td=document.createElement('td');
  if(cls){const span=document.createElement('span');span.className=cls;span.textContent=String(value);td.append(span);}
  else td.textContent=String(value);
  row.append(td);
}
function drawTable(){
  if(!report)return;
  const query=view.search.value.trim().toLowerCase();
  const selectedRows=report.results.filter(item=>
    (filter==='all'||item.action===filter)&&
    (!query||item.alertId.toLowerCase().includes(query)||
      item.source.toLowerCase().includes(query)||
      (item.destination||'').toLowerCase().includes(query)||
      item.description.toLowerCase().includes(query))
  );
  view.body.replaceChildren();
  if(!selectedRows.length){
    const tr=document.createElement('tr'),td=document.createElement('td');
    td.colSpan=8;td.className='empty-state';td.textContent='검색에 맞는 경보가 없습니다.';
    tr.append(td);view.body.append(tr);
  }
  for(const item of selectedRows){
    const tr=document.createElement('tr');
    tr.tabIndex=0;tr.title='선택한 외부 전송 경보 분석';
    tr.className=selected===item.alertId?'selected-row':'';
    cell(tr,item.alertId,'row-id');
    cell(tr,item.description);
    cell(tr,item.source);
    cell(tr,item.destination||'–');
    cell(tr,size(item.bytes));
    cell(tr,item.level);
    cell(tr,Math.round(item.confidence*100)+'%');
    cell(tr,actionNames[item.action],'action-chip '+item.action);
    const pick=()=>{
      choose(item.alertId);
      $('lab').scrollIntoView({behavior:'smooth',block:'start'});
    };
    tr.addEventListener('click',pick);
    tr.addEventListener('keydown',event=>{
      if(event.key==='Enter'||event.key===' '){event.preventDefault();pick();}
    });
    view.body.append(tr);
  }
  setText(view.shown,selectedRows.length+' / '+report.fixtureCount+'건 표시');
}
for(const btn of document.querySelectorAll('[data-case]'))
  btn.addEventListener('click',()=>choose(btn.dataset.case));
for(const btn of document.querySelectorAll('[data-filter]'))
  btn.addEventListener('click',()=>{
    filter=btn.dataset.filter;
    for(const item of document.querySelectorAll('[data-filter]')){
      const active=item===btn;
      item.classList.toggle('selected',active);
      item.setAttribute('aria-pressed',String(active));
    }
    drawTable();
  });
view.search.addEventListener('input',drawTable);
$('replay').addEventListener('click',()=>choose(selected,true));

try{
  const [response,fixture]=await Promise.all(['/report.json','/samples.json'].map(async url=>{
    const r=await fetch(url,{cache:'no-store'});
    if(!r.ok)throw new Error('Unable to load '+url);
    return r.json();
  }));
  if(response.moduleKey!=='exfiltration'||response.schema!=='aleph.xdr.result.v1'||
     !Array.isArray(response.results)||!Array.isArray(fixture.alerts)||
     response.results.length!==fixture.alerts.length)
    throw new Error('Invalid XDR-06 training report');
  report=response;samples=fixture.alerts;
  for(const [key,value] of Object.entries({
    'm-total':response.fixtureCount,'m-block':response.counts.block,
    'm-alert':response.counts.alert,'m-record':response.counts.record,
    'm-false':response.normalBlocked
  }))setText($(key),value);
  choose(samples.some(x=>x.id===selected)?selected:samples[0].id);
}catch(error){
  view.body.replaceChildren();
  const tr=document.createElement('tr'),td=document.createElement('td');
  td.colSpan=8;td.className='empty-state';
  td.textContent='분석 데이터를 불러오지 못했습니다. 결과 파일 생성 상태를 확인해 주세요.';
  tr.append(td);view.body.append(tr);
  setText(view.status,'교육용 결과 파일을 읽지 못했습니다.');
  console.error('XDR-06 dashboard:',error.message);
}
