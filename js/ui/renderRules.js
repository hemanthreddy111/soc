import { findTechnique } from '../data/mitre.js';
import { esc } from '../utils/helpers.js';

// A table of every detection rule in js/data/rules.js
export function renderRules(rules) {
  const rows = rules.map(r => `
    <tr><td>${r.id}</td><td>${esc(r.name)}</td><td>${r.technique} ${esc(findTechnique(r.technique).name)}</td>
    <td><span class="pill" style="--sev: var(--sev-${r.severity})">${r.severity}</span></td><td>${esc(r.logic)}</td></tr>`).join('');
  return `<table><tr><th>ID</th><th>Rule</th><th>ATT&amp;CK technique</th><th>Severity</th><th>Logic</th></tr>${rows}</table>`;
}
