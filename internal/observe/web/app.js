'use strict';
const byId = id => document.getElementById(id);
const number = value => Number(value).toLocaleString('en-US');
let previous = null;
let inFlight = false;

function table(id, rows, fields, message) {
  const body = byId(id);
  const fragment = document.createDocumentFragment();
  if (!rows.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = fields.length;
    cell.className = 'empty';
    cell.textContent = message;
    row.appendChild(cell); fragment.appendChild(row);
  }
  for (const item of rows) {
    const row = document.createElement('tr');
    for (const field of fields) {
      const cell = document.createElement('td');
      cell.textContent = typeof field === 'function' ? field(item) : (item[field] ?? '—');
      row.appendChild(cell);
    }
    fragment.appendChild(row);
  }
  body.replaceChildren(fragment);
}

async function update() {
  if (inFlight) return;
  inFlight = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 900);
  try {
    const paths = ['/stats.json', '/jail.json', '/log.json', '/health.json'];
    const [s, jail, events, health] = await Promise.all(paths.map(async path => {
      const response = await fetch(path, {cache: 'no-store', signal: controller.signal});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return response.json();
    }));
    const now = performance.now();
    const seconds = previous ? (now - previous.time) / 1000 : 0;
    const validRate = previous && seconds > 0 && s.passed >= previous.passed && s.dropped >= previous.dropped;
    byId('pass-rate').textContent = validRate ? number(Math.round((s.passed - previous.passed) / seconds)) : '—';
    byId('drop-rate').textContent = validRate ? number(Math.round((s.dropped - previous.dropped) / seconds)) : '—';
    previous = {time: now, passed: s.passed, dropped: s.dropped};
    for (const key of ['passed', 'dropped', 'bounced', 'honeypotted', 'malformed', 'other', 'jailed']) byId(key).textContent = number(s[key]);
    byId('default-hits').textContent = number(s.default_hits);
    byId('generation').textContent = 'Policy v' + s.rules_version;
    byId('jail-count').textContent = number(s.jailed_sources) + ' jailed';
    byId('sets').textContent = 'Address sets: ' + (s.sets.map(set => set.name + ' (' + set.prefixes + ')').join(' · ') || 'none');
    table('rules', s.rules, ['line', 'hits', 'passed', 'dropped', 'bounced', 'honeypotted'], 'No rules — fragment/default policy applies.');
    table('sources', s.top_sources, ['src', 'packets'], 'No IP sources yet.');
    table('jail', jail, ['src', 'seconds_left'], 'Everyone is behaving.');
    table('events', events.slice(-20), ['line', 'verdict', 'src', 'dst', 'proto', 'sport', 'dport'], 'No logged rule decisions yet.');
    const failures = Object.entries(health).filter(([key, value]) => key === 'events_read' ? false : key === 'stream_error' ? Boolean(value) : Number(value) !== 0);
    byId('warning').hidden = !failures.length;
    byId('warning').textContent = 'Telemetry degraded: ' + failures.map(([key, value]) => key + '=' + value).join(' · ');
    byId('status').textContent = 'LIVE / XDP ACTIVE';
    byId('led').className = 'led live';
  } catch (error) {
    previous = null;
    byId('status').textContent = 'OFFLINE / RETRYING';
    byId('led').className = 'led offline';
  } finally {
    clearTimeout(timeout);
    inFlight = false;
  }
}
update();
setInterval(update, 1000);
