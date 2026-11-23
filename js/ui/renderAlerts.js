import { esc, fmtTime, SEVERITY_RANK } from '../utils/helpers.js';

// The list of alerts, most severe first.
export function renderAlerts(alerts, selectedId, techFilter) {
  const shown = alerts
    .filter(a => !techFilter || a.rule.technique === techFilter)
    .sort((a, b) => SEVERITY_RANK[b.rule.severity] - SEVERITY_RANK[a.rule.severity] || a.time - b.time);

  if (!shown.length) return '<p>No alerts. Replay the sample attack or load your own logs.</p>';

  return shown.map(a => `
    <button class="alert ${a.status !== 'open' ? 'done' : ''}" data-id="${a.id}"
      style="--sev: var(--sev-${a.rule.severity})" aria-pressed="${a.id === selectedId}">
      <b>${esc(a.rule.name)}</b>
      <small>${esc(a.entity)} at ${fmtTime(a.time)} UTC, ${a.rule.technique}, ${a.status}</small>
    </button>`).join('');
}
