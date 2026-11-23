# SOC Detection & Response Platform

A browser-based mini SOC: it reads log events, runs detection rules, maps every alert to MITRE ATT&CK, and lets you simulate a response. No build step, no dependencies.

## Deploy on Vercel
1. Push this folder to a GitHub repo, then in Vercel choose **Add New > Project** and import it. Leave every setting as default (Framework: Other, no build command).
2. Or from this folder run `npx vercel --prod`.

To run locally: `npx serve .` (ES modules need a server, so opening index.html by double-click will not work).

## How it works
```
index.html                 page layout
css/theme.css              colors (edit these to match your portfolio)
css/style.css              all styling
js/main.js                 connects everything and handles clicks
js/data/rules.js           detection rules (add yours here)
js/data/mitre.js           ATT&CK techniques shown in the grid
js/data/sampleLogs.js      fake logs with a staged attack
js/engine/detectionEngine.js   runs rules over events -> alerts
js/engine/responseActions.js   simulated block / isolate / disable
js/ui/*.js                 one file per section of the screen
js/utils/helpers.js        small shared functions
```

## Add a detection rule
Copy a block in `js/data/rules.js`, change the `id`, `technique` (add it to `mitre.js` if new), and the `filter` function. Refresh and it shows up in the rules table, the ATT&CK grid and the alerts.

## Use your own logs
Click **Load your logs (JSON)**. File format: an array of events, for example
`[{ "time": "2026-11-23T09:00:00Z", "type": "login_failed", "srcIp": "1.2.3.4", "user": "admin", "host": "SRV1" }]`.
Event types the rules understand: login_failed, login_success, net_connect, process_create, schtask_create, user_create, rdp_login, net_out, file_rename, log_cleared.
