// Four summary cards at the top of the page.
export function renderStats(events, alerts, rules) {
  const open = alerts.filter(a => a.status === 'open').length;
  const hit = new Set(alerts.map(a => a.rule.technique)).size;
  const cards = [
    [events.length, 'Events analysed'],
    [alerts.length, 'Alerts raised'],
    [open, 'Still open'],
    [`${hit} of ${new Set(rules.map(r => r.technique)).size}`, 'ATT&CK techniques triggered'],
  ];
  return cards.map(([n, label]) => `<div class="stat"><b>${n}</b><span>${label}</span></div>`).join('');
}
