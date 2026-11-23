import { findTechnique, techniqueUrl } from '../data/mitre.js';
import { ACTION_LABELS } from '../engine/responseActions.js';
import { esc, fmtTime } from '../utils/helpers.js';

// The investigation panel: why the alert fired, the evidence, and what to do about it.
export function renderDetail(alert) {
  if (!alert) return '<p>Select an alert to see the evidence and response options.</p>';

  const { rule } = alert;
  const tech = findTechnique(rule.technique);
  const rows = alert.evidence.slice(0, 12).map(e => `
    <tr><td>${fmtTime(e.time)}</td><td>${esc(e.type)}</td><td>${esc(e.host)}</td>
    <td>${esc(e.user)}</td><td>${esc(e.srcIp)}</td><td><code>${esc(e.cmd || e.dstIp)}</code></td></tr>`).join('');
  const more = alert.evidence.length > 12 ? `<p>Showing 12 of ${alert.evidence.length} events.</p>` : '';

  const buttons = alert.status === 'open' ? `
    <div class="actions">
      <button class="btn" data-action="${rule.response.action}">
        ${ACTION_LABELS[rule.response.action]}: ${esc(alert.evidence[0][rule.response.field])}</button>
      <button class="btn ghost" data-action="dismiss">${ACTION_LABELS.dismiss}</button>
    </div>` : '';
  const log = alert.responses.map(r =>
    `<p class="log">${fmtTime(r.at)} UTC: ${esc(r.label)} ${esc(r.target)}</p>`).join('');

  return `
    <h3>${esc(rule.name)} <span class="pill" style="--sev: var(--sev-${rule.severity})">${rule.severity}</span></h3>
    <p>${esc(rule.logic)}.</p>
    <p class="row">ATT&amp;CK: <a href="${techniqueUrl(tech.id)}" target="_blank" rel="noopener">${tech.id} ${esc(tech.name)}</a> (${esc(tech.tactic)})</p>
    <div class="scroll-x"><table>
      <tr><th>Time</th><th>Event</th><th>Host</th><th>User</th><th>Source</th><th>Detail</th></tr>${rows}
    </table></div>${more}${buttons}${log}`;
}
