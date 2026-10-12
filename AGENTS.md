# ALEPH XDR-06 / Data exfiltration defense
- Work ONLY in this ALEPH-XDR-06-Exfiltration repository; never touch XDR-01..05.
- Keep ChoiTimo original `xdr/fixtures/exfiltration.json` with all 30 alerts and the official `scripts/xdr-run.mjs` unmodified.
- `xdr/exfiltration/decide.mjs` is pure, standalone and imports nothing. No IO, clock, network, runtime patterns.json import, or external libraries.
- Confidence >=0.85 block, >=0.50 alert, otherwise record. Strong exfiltration must require actual substantial transfer and corroborating risky destination/behavior.
- This assignment blocks only confirmed EXTERNAL DESTINATIONS. Never implement source IP or account block in the ZTNA adapter.
- `respond.mjs` owns file effects: 15-minute destination deny policies with alertId and one-line notifications in `xdr/alerts.log`. Keep `ztna/rules.json` unchanged.
- Sanitize training logs; never publish credentials, headers, tokens, raw logs, or private environment files.
- Static Vercel page is educational and shows offline fixture replay, not live Wazuh detection or real network blocking.
- Run `npm run xdr:run -- exfiltration`, `npm test`, `npm run build` and verify generated artifacts with GitHub Actions.
