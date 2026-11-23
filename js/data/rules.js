// Detection rules. Each rule says: what to look for, how bad it is, and which ATT&CK technique it maps to.
//
// type 'single'    -> one matching event raises an alert.
// type 'threshold' -> several matching events raise an alert, using:
//     groupBy   count events per this field (e.g. one source IP)
//     threshold how many events are needed
//     windowSec within how many seconds
//     distinct  (optional) count different values of this field instead of all events
//
// response -> the suggested fix: which action, and which event field to act on.

export const RULES = [
  {
    id: 'R001', name: 'Brute-force login attempts', technique: 'T1110', severity: 'high',
    type: 'threshold', logic: '5 or more failed logins from one IP within 2 minutes',
    filter: e => e.type === 'login_failed', groupBy: 'srcIp', threshold: 5, windowSec: 120,
    response: { action: 'block_ip', field: 'srcIp' },
  },
  {
    id: 'R002', name: 'Port scan', technique: 'T1046', severity: 'medium',
    type: 'threshold', logic: 'One IP connects to 10 or more different ports within 30 seconds',
    filter: e => e.type === 'net_connect', groupBy: 'srcIp', distinct: 'dstPort', threshold: 10, windowSec: 30,
    response: { action: 'block_ip', field: 'srcIp' },
  },
  {
    id: 'R003', name: 'Encoded PowerShell command', technique: 'T1059.001', severity: 'high',
    type: 'single', logic: 'A process starts with PowerShell and an encoded command (-enc)',
    filter: e => e.type === 'process_create' && /powershell/i.test(e.cmd) && /-enc/i.test(e.cmd),
    response: { action: 'isolate_host', field: 'host' },
  },
  {
    id: 'R004', name: 'LSASS credential dumping', technique: 'T1003', severity: 'critical',
    type: 'single', logic: 'A process command mentions lsass or mimikatz',
    filter: e => e.type === 'process_create' && /lsass|mimikatz/i.test(e.cmd),
    response: { action: 'isolate_host', field: 'host' },
  },
  {
    id: 'R005', name: 'Scheduled task created', technique: 'T1053.005', severity: 'medium',
    type: 'single', logic: 'A new scheduled task is created',
    filter: e => e.type === 'schtask_create',
    response: { action: 'isolate_host', field: 'host' },
  },
  {
    id: 'R006', name: 'New local account created', technique: 'T1136', severity: 'high',
    type: 'single', logic: 'A new user account is added to a machine',
    filter: e => e.type === 'user_create',
    response: { action: 'disable_user', field: 'user' },
  },
  {
    id: 'R007', name: 'RDP to many hosts', technique: 'T1021.001', severity: 'high',
    type: 'threshold', logic: 'One source reaches 3 or more different hosts over RDP within 5 minutes',
    filter: e => e.type === 'rdp_login', groupBy: 'srcIp', distinct: 'host', threshold: 3, windowSec: 300,
    response: { action: 'disable_user', field: 'user' },
  },
  {
    id: 'R008', name: 'Large outbound transfer', technique: 'T1048', severity: 'high',
    type: 'single', logic: 'More than 50 MB is sent to an outside address in one connection',
    filter: e => e.type === 'net_out' && e.bytesOut > 50_000_000,
    response: { action: 'block_ip', field: 'dstIp' },
  },
  {
    id: 'R009', name: 'Mass file renaming (ransomware)', technique: 'T1486', severity: 'critical',
    type: 'threshold', logic: '20 or more files renamed on one host within 1 minute',
    filter: e => e.type === 'file_rename', groupBy: 'host', threshold: 20, windowSec: 60,
    response: { action: 'isolate_host', field: 'host' },
  },
  {
    id: 'R010', name: 'Security log cleared', technique: 'T1070.001', severity: 'high',
    type: 'single', logic: 'The Windows Security event log is cleared',
    filter: e => e.type === 'log_cleared',
    response: { action: 'isolate_host', field: 'host' },
  },
];
