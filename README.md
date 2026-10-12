# ALEPH XDR-06 · 자료 빼돌리기를 잡아 냅니다

MITRE ATT&CK **T1041(명령 통로를 이용한 자료 유출)**과 **T1048(다른 프로토콜을 이용한 자료 유출)**에 대한 Wazuh 경보 분석 및 목적지 임시 거부 실습입니다.

**공개 대시보드:** https://sdy-xdr-06.vercel.app  
**공개 소스:** https://github.com/sdydy0298-dotcom/ALEPH-XDR-06-Exfiltration

> 실제 Wazuh 관제 시스템·방화벽을 연결하지 않은 **교육용 오프라인 시뮬레이션**입니다. 수업용 가상 로그와 파일 기반 ZTNA 판정기를 통해 차단 대상을 검증합니다. 대시보드의 DENY/ALLOW는 실제 네트워크 차단이 아닙니다.

## 원본 데이터와 실행 방법

- [ChoiTimo 공식 `xdr/fixtures/exfiltration.json`](https://github.com/ChoiTimo/aleph-defense-starter/blob/main/xdr/fixtures/exfiltration.json) — **30건, 원본 내용 보존**
- 공식 `scripts/xdr-run.mjs` — **원본 내용 보존**
- `aleph.xdr.fixture.v1` 입력 → `aleph.xdr.result.v1` 출력

```bash
npm run xdr:run -- exfiltration
npm test
npm run build
```

**자체 실행 결과:** BLOCK **10** · ALERT **10** · RECORD **10** · 정상 이벤트 오차단 **0**. 명확한 경보 10건에 대해 임시 거부 규칙 10개가 만들어지며 실제 목적지는 중복을 제외해 8개입니다. 알림 로그는 BLOCK+ALERT **20줄**입니다.

## 제작 1~5 및 제출 요구사항

| 단계 | 결과 |
|---|---|
| 1. 경보 읽기 | `xdr/exfiltration/read-alerts.mjs`: 30건 → 30줄, 시각·출발 주소·계정·규칙 수준·설명만 추출, 비밀 문자열 마스킹 |
| 2. 패턴 | `xdr/exfiltration/patterns.json`: T1041/T1048에 근거한 낯선 목적지 대량 전송, 반복 반출, 시간 외 압축 전송 등 패턴의 한 줄 증거 |
| 3. 판단 | `xdr/exfiltration/decide.mjs`: 독립 `decide(alert)` 함수, import 없음, 파일·네트워크 접근 없음. 0.85 이상 BLOCK / 0.50 이상 ALERT / 미만 RECORD |
| 4. 응답 | `xdr/exfiltration/respond.mjs`: BLOCK 후보를 **목적지 IP별** 15분 임시 거부 정책에 추가, 경보 ID와 만료시각 포함. ALERT는 알림만 기록 |
| 5. 시험 | `xdr/run.mjs`: 공식 실행기로 `xdr/exfiltration/result.json` 재생, 정상 목적지 허용 및 15분 후 거부 해제 검증 |
| 최종 | `.github/workflows/check.yml`: 공식 실행·동작 테스트·재실행·사이트 빌드·생성 파일 일치 검사 |

### 가장 중요한 안전 제약

1. **출발 IP나 사용자 계정은 차단하지 않습니다.** 오직 외부 반출 **목적지** `destination`을 기존 ZTNA 판정기의 추가 거부 조건으로 검사합니다.
2. 전송 실패·압축 파일만 생성한 경우·실제 전송이 없는 이벤트는 BLOCK에 올리지 않습니다.
3. 정상 전송이나 일시적인 비정상 규모는 BLOCK이 아니라 ALERT 또는 RECORD로 구분합니다.
4. 원래 `ztna/rules.json`은 파일을 읽기만 하고 수정하지 않습니다. 기존 정책과 `xdr/temporary-deny.json`의 임시 거부 규칙을 함께 검사합니다.
5. `xdr/alerts.log`에는 경보 ID·판정·확신도·패턴명·확인시각만 저장하여 계정·비밀번호·실제 전송 내용이 유출되지 않도록 합니다.

`public/decide.mjs`는 원본 단독 판정기와 동일한 코드입니다. 브라우저에서 공식 경보를 클릭하고 실제 판단 과정을 재실행해볼 수 있으며 서버로 경보 데이터를 업로드하지 않습니다.

판정의 고정 시각은 `2026-10-13T00:00:00Z`이며 15분 뒤 자동 만료되는 정책을 **과거 기준 시각**으로 재현합니다. 실제 서비스에서는 공동 CDN/IP를 막을 위험을 평가해야 합니다. 심판의 비공개 정답표까지 일치하는지는 제출 후 확인 가능합니다.

**이 저장소는 XDR-01~05와 독립이며 다른 과제의 GitHub 파일이나 Vercel 배포는 수정하지 않았습니다.**
