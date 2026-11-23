// Entry point: connects the data, the engine and the screen.
import { RULES } from './data/rules.js';
import { generateLogs } from './data/sampleLogs.js';
import { runDetections } from './engine/detectionEngine.js';
import { applyAction } from './engine/responseActions.js';
import { renderStats } from './ui/renderStats.js';
import { renderMitre } from './ui/renderMitre.js';
import { renderAlerts } from './ui/renderAlerts.js';
import { renderDetail } from './ui/renderDetail.js';
import { renderRules } from './ui/renderRules.js';

const $ = id => document.getElementById(id);
const state = { events: [], alerts: [], selectedId: null, techFilter: null };

// Run the detections on a set of events and refresh the screen
function load(events) {
  state.events = events;
  state.alerts = runDetections(events, RULES);
  state.techFilter = null;
  state.selectedId = state.alerts[0]?.id ?? null;
  draw();
}

function draw() {
  const selected = state.alerts.find(a => a.id === state.selectedId);
  $('stats').innerHTML = renderStats(state.events, state.alerts, RULES);
  $('mitre').innerHTML = renderMitre(state.alerts, RULES, state.techFilter);
  $('alerts').innerHTML = renderAlerts(state.alerts, state.selectedId, state.techFilter);
  $('detail').innerHTML = renderDetail(selected);
  $('rules').innerHTML = renderRules(RULES);
}

// Click an alert -> show its details
$('alerts').addEventListener('click', e => {
  const item = e.target.closest('[data-id]');
  if (item) { state.selectedId = item.dataset.id; draw(); }
});

// Click a triggered technique -> filter alerts (click again to clear)
$('mitre').addEventListener('click', e => {
  const cell = e.target.closest('.tech.triggered');
  if (cell) { state.techFilter = state.techFilter === cell.dataset.tech ? null : cell.dataset.tech; draw(); }
});

// Click a response button -> apply the action to the selected alert
$('detail').addEventListener('click', e => {
  const button = e.target.closest('[data-action]');
  const alert = state.alerts.find(a => a.id === state.selectedId);
  if (button && alert) { applyAction(alert, button.dataset.action); draw(); }
});

$('btn-replay').addEventListener('click', () => { $('notice').textContent = ''; load(generateLogs()); });

// Load your own logs: a JSON array like [{ "time": "2026-11-23T09:00:00Z", "type": "login_failed", "srcIp": "1.2.3.4" }]
$('file').addEventListener('change', async e => {
  try {
    const rows = JSON.parse(await e.target.files[0].text());
    const events = rows
      .map((r, i) => ({ type: '', host: '-', user: '-', srcIp: '-', dstIp: '-', dstPort: 0, cmd: '', bytesOut: 0, ...r, time: new Date(r.time).getTime(), id: i + 1 }))
      .sort((a, b) => a.time - b.time);
    $('notice').textContent = `Loaded ${events.length} events from your file.`;
    load(events);
  } catch {
    $('notice').textContent = 'Could not read that file. It must be a JSON array of events, each with a "time" and a "type".';
  }
});

load(generateLogs());
