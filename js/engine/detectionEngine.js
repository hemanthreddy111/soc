// The detection engine: runs every rule over the events and returns alerts.
// It knows nothing about the screen, so you can test it on its own.

let alertCounter = 0;

export function runDetections(events, rules) {
  const alerts = [];

  for (const rule of rules) {
    const matches = events.filter(rule.filter);

    if (rule.type === 'single') {
      // One matching event = one alert
      matches.forEach(e => alerts.push(makeAlert(rule, [e], e.host)));
    } else {
      // Threshold rule: group events (e.g. by IP), then look for a burst inside the time window
      const groups = {};
      matches.forEach(e => (groups[e[rule.groupBy]] ||= []).push(e));
      for (const [key, list] of Object.entries(groups)) {
        const burst = findBurst(list, rule);
        if (burst) alerts.push(makeAlert(rule, burst, key));
      }
    }
  }
  return alerts;
}

// Slide a time window over the events and return the first window that reaches the threshold.
// (Events must be sorted by time, which generateLogs already does.)
function findBurst(list, rule) {
  let start = 0;
  for (let end = 0; end < list.length; end++) {
    while (list[end].time - list[start].time > rule.windowSec * 1000) start++;
    const windowEvents = list.slice(start, end + 1);
    const count = rule.distinct
      ? new Set(windowEvents.map(e => e[rule.distinct])).size
      : windowEvents.length;
    if (count >= rule.threshold) return windowEvents;
  }
  return null;
}

function makeAlert(rule, evidence, entity) {
  return {
    id: `${rule.id}-${++alertCounter}`,
    rule, entity, evidence,
    time: evidence[0].time,
    status: 'open',      // open -> contained | dismissed
    responses: [],       // actions taken by the analyst
  };
}
