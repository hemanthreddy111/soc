// Builds fake log events: normal office activity plus a staged attack.
// A seeded random generator means you get the same logs every time.

const START = Date.UTC(2026, 10, 23, 9, 0, 0); // 09:00:00 UTC

function seededRandom(seed) {
  let s = seed;
  return () => (s = (s * 1664525 + 1013904223) % 4294967296) / 4294967296;
}

export function generateLogs() {
  const rand = seededRandom(7);
  const pick = list => list[Math.floor(rand() * list.length)];
  const events = [];

  // add(secondsAfterStart, fields) fills in defaults so every event has the same shape
  const add = (sec, fields) => events.push({
    time: START + sec * 1000, type: '', host: '-', user: '-', srcIp: '-',
    dstIp: '-', dstPort: 0, cmd: '', bytesOut: 0, ...fields,
  });

  // 1) Normal background activity
  for (let i = 0; i < 150; i++) {
    add(i * 24, { type: 'login_success', host: pick(['WS-001', 'WS-002', 'WS-003', 'SRV-FILE']),
      user: pick(['asha', 'ravi', 'meena', 'kiran']), srcIp: '10.0.0.' + (10 + Math.floor(rand() * 30)) });
    if (i % 10 === 0) add(i * 24 + 5, { type: 'login_failed', host: 'WS-002', user: 'ravi', srcIp: '10.0.0.21' });
    if (i % 7 === 0) add(i * 24 + 9, { type: 'process_create', host: 'WS-001', user: 'asha', cmd: 'chrome.exe --new-tab' });
  }

  // 2) Attacker from the internet scans, then brute-forces the web server
  const attacker = '185.220.101.7';
  for (let p = 20; p < 36; p++) add(1100 + (p - 20), { type: 'net_connect', host: 'SRV-WEB01', srcIp: attacker, dstIp: '10.0.0.5', dstPort: p });
  for (let i = 0; i < 8; i++) add(1200 + i * 5, { type: 'login_failed', host: 'SRV-WEB01', user: 'admin', srcIp: attacker });
  add(1245, { type: 'login_success', host: 'SRV-WEB01', user: 'admin', srcIp: attacker });

  // 3) A workstation (WS-014) is compromised and the attacker moves through the network
  const ws = { host: 'WS-014', user: 'kiran', srcIp: '10.0.0.14' };
  add(2000, { ...ws, type: 'process_create', cmd: 'powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0A' });
  add(2060, { ...ws, type: 'process_create', cmd: 'rundll32.exe comsvcs.dll MiniDump lsass.exe' });
  add(2120, { ...ws, type: 'schtask_create', cmd: 'schtasks /create /tn Updater /tr C:\\Temp\\u.exe' });
  add(2180, { ...ws, type: 'user_create', cmd: 'net user support$ /add' });
  ['SRV-FILE', 'SRV-DB', 'SRV-WEB01'].forEach((host, i) =>
    add(2300 + i * 30, { ...ws, type: 'rdp_login', host, dstIp: '10.0.0.' + (50 + i) }));
  add(2600, { ...ws, type: 'net_out', dstIp: '45.9.148.22', dstPort: 443, bytesOut: 120_000_000 });
  for (let i = 0; i < 25; i++) add(2800 + i, { ...ws, type: 'file_rename', cmd: `file${i}.docx -> file${i}.docx.locked` });
  add(2900, { ...ws, type: 'log_cleared', cmd: 'wevtutil cl Security' });

  return events.sort((a, b) => a.time - b.time).map((e, i) => ({ id: i + 1, ...e }));
}
