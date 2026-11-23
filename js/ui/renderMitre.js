import { TACTICS } from '../data/mitre.js';
import { esc } from '../utils/helpers.js';

// The ATT&CK grid. Each technique is one of:
//   triggered = an alert fired (click to filter alerts)
//   covered   = we have a rule, nothing fired
//   gap       = no rule yet (dashed)
export function renderMitre(alerts, rules, selectedTech) {
  const counts = {};
  alerts.forEach(a => (counts[a.rule.technique] = (counts[a.rule.technique] || 0) + 1));
  const covered = new Set(rules.map(r => r.technique));

  const columns = TACTICS.map(t => {
    const cells = t.techniques.map(([id, name]) => {
      const state = counts[id] ? 'triggered' : covered.has(id) ? 'covered' : 'gap';
      const sel = selectedTech === id ? ' selected' : '';
      return `<button class="tech ${state}${sel}" data-tech="${id}" ${state === 'triggered' ? '' : 'tabindex="-1"'}>
        <b>${id}</b>${esc(name)}${counts[id] ? `<i>${counts[id]}</i>` : ''}</button>`;
    }).join('');
    return `<div class="tactic"><h3>${esc(t.name)}</h3>${cells}</div>`;
  }).join('');

  return columns + '<p class="legend">Filled = alert fired (click to filter). Solid outline = rule exists. Dashed = no rule yet.</p>';
}
