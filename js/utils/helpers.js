// Small helper functions used by the UI files.

// Escape text before putting it into HTML (protects against XSS from uploaded logs).
export function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// 1700000000000 -> "09:20:45" (UTC)
export function fmtTime(ms) {
  return new Date(ms).toISOString().slice(11, 19);
}

// Used to sort alerts: critical first.
export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
