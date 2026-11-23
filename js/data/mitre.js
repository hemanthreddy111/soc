// A small slice of the MITRE ATT&CK Enterprise matrix.
// Add more techniques here and they appear in the coverage grid automatically.
export const TACTICS = [
  { name: 'Initial Access',       techniques: [['T1566', 'Phishing'], ['T1190', 'Exploit Public-Facing App']] },
  { name: 'Execution',            techniques: [['T1059.001', 'PowerShell']] },
  { name: 'Persistence',          techniques: [['T1053.005', 'Scheduled Task'], ['T1136', 'Create Account']] },
  { name: 'Privilege Escalation', techniques: [['T1548', 'Abuse Elevation Control']] },
  { name: 'Defense Evasion',      techniques: [['T1070.001', 'Clear Windows Event Logs'], ['T1562', 'Impair Defenses']] },
  { name: 'Credential Access',    techniques: [['T1110', 'Brute Force'], ['T1003', 'OS Credential Dumping']] },
  { name: 'Discovery',            techniques: [['T1046', 'Network Service Discovery'], ['T1087', 'Account Discovery']] },
  { name: 'Lateral Movement',     techniques: [['T1021.001', 'Remote Desktop Protocol']] },
  { name: 'Command and Control',  techniques: [['T1071', 'Application Layer Protocol']] },
  { name: 'Exfiltration',         techniques: [['T1048', 'Exfiltration Over Alternative Protocol']] },
  { name: 'Impact',               techniques: [['T1486', 'Data Encrypted for Impact']] },
];

// Look up one technique by ID, e.g. findTechnique('T1110')
export function findTechnique(id) {
  for (const tactic of TACTICS) {
    for (const [tid, name] of tactic.techniques) {
      if (tid === id) return { id, name, tactic: tactic.name };
    }
  }
  return { id, name: id, tactic: 'Unknown' };
}

// T1059.001 -> https://attack.mitre.org/techniques/T1059/001/
export function techniqueUrl(id) {
  return 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/';
}
