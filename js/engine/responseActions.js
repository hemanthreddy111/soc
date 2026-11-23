// Simulated response actions. In a real SOC these would call a firewall, EDR or identity API.

export const ACTION_LABELS = {
  block_ip: 'Block IP',
  isolate_host: 'Isolate host',
  disable_user: 'Disable user',
  dismiss: 'Mark as false positive',
};

export function applyAction(alert, action) {
  const target = action === 'dismiss' ? '' : alert.evidence[0][alert.rule.response.field];
  alert.status = action === 'dismiss' ? 'dismissed' : 'contained';
  alert.responses.push({ label: ACTION_LABELS[action], target, at: new Date() });
}
