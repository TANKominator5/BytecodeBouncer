'use strict';

/* Helpers */
const byId = id => document.getElementById(id);
const formatNumber = value => Number(value || 0).toLocaleString('en-US');
const sampleLimit = 30;
const endpoints = ['/stats.json', '/jail.json', '/log.json', '/health.json'];
const chartOptions = Array.from(document.querySelectorAll('.chart-option'));
const verdictClasses = {PASS: 'pass', DROP: 'drop', BOUNCE: 'bounce', HONEYPOT: 'honeypot'};
const chartModes = {
  diverging: {
    pass: 'PASS ↑',
    middle: '0',
    drop: 'DROP ↓'
  },
  stacked: {
    pass: 'PASS',
    middle: 'TOTAL ↑',
    drop: 'DROP'
  }
};

let chartMode = 'diverging';
let previousSample = null;
let history = [];
let inFlight = false;

/* Tables */
function renderTable(id, rows, columns, emptyMessage) {
  const body = byId(id);
  const fragment = document.createDocumentFragment();
  if (!rows.length) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = columns.length;
    cell.className = 'empty';
    cell.textContent = emptyMessage;
    row.appendChild(cell);
    fragment.appendChild(row);
  }
  for (const item of rows) {
    const row = document.createElement('tr');
    for (const column of columns) {
      const cell = document.createElement('td');
      const value = column.value(item);
      if (value instanceof Node) cell.appendChild(value);
      else cell.textContent = value == null ? '—' : String(value);
      row.appendChild(cell);
    }
    fragment.appendChild(row);
  }
  body.replaceChildren(fragment);
}

function activityCell(rule, maxHits) {
  const activity = document.createElement('span');
  activity.className = 'rule-hit-cell';
  const count = document.createElement('span');
  count.textContent = formatNumber(rule.hits);
  const track = document.createElement('span');
  track.className = 'rule-hit-track';
  track.setAttribute('aria-hidden', 'true');
  const fill = document.createElement('span');
  fill.className = 'rule-hit-fill';
  fill.style.width = `${rule.hits / maxHits * 100}%`;
  track.appendChild(fill);
  activity.append(count, track);
  return activity;
}

function verdictBadge(event) {
  const badge = document.createElement('span');
  badge.className = `verdict verdict-${verdictClasses[event.verdict] || 'drop'}`;
  badge.textContent = event.verdict;
  return badge;
}

/* Chart */
function renderChart() {
  const root = byId('chart-samples');
  const fragment = document.createDocumentFragment();
  const stacked = chartMode === 'stacked';
  const maxRate = Math.max(1, ...history.map(sample => stacked
    ? sample.pass + sample.drop
    : Math.max(sample.pass, sample.drop)));
  const slots = Array(sampleLimit - history.length).fill(null).concat(history);
  for (const sample of slots) {
    const column = document.createElement('span');
    column.className = sample ? 'sample' : 'sample empty';
    const pass = document.createElement('span');
    pass.className = 'sample-pass';
    const drop = document.createElement('span');
    drop.className = 'sample-drop';
    if (sample) {
      if (stacked) {
        pass.style.height = `${Math.max(0, sample.pass / maxRate * 100)}%`;
        drop.style.height = `${Math.max(0, sample.drop / maxRate * 100)}%`;
      } else {
        pass.style.height = `${Math.max(0, sample.pass / maxRate * 48)}%`;
        drop.style.height = `${Math.max(0, sample.drop / maxRate * 48)}%`;
      }
      pass.title = `Pass ${formatNumber(sample.pass)} packets/sec`;
      drop.title = `Drop ${formatNumber(sample.drop)} packets/sec`;
    }
    if (stacked) {
      const stack = document.createElement('span');
      stack.className = 'sample-stack';
      stack.append(drop, pass);
      column.appendChild(stack);
    } else {
      column.append(pass, drop);
    }
    fragment.appendChild(column);
  }
  root.replaceChildren(fragment);

  const latest = history.at(-1);
  const chartState = byId('chart-state');
  chartState.hidden = history.length > 0;
  chartState.textContent = previousSample ? 'WAITING FOR NEXT SNAPSHOT' : 'WAITING FOR FIRST SNAPSHOT';
  byId('traffic-chart').setAttribute('aria-label', latest
    ? `${stacked ? 'Stacked bar chart' : 'Diverging chart'} of recent packet rates. Latest sample: ${formatNumber(latest.pass)} passed packets per second and ${formatNumber(latest.drop)} dropped packets per second. ${history.length} of ${sampleLimit} intervals shown.`
    : 'Waiting for a second successful stats sample before calculating packet rates.');
}

function updateChartMode() {
  const mode = chartModes[chartMode];
  byId('traffic-chart').classList.toggle('stacked', chartMode === 'stacked');
  byId('axis-pass').textContent = mode.pass;
  byId('axis-middle').textContent = mode.middle;
  byId('axis-drop').textContent = mode.drop;
  for (const option of chartOptions) {
    option.setAttribute('aria-pressed', String(option.dataset.chart === chartMode));
  }
}

/* Sources */
function renderSources(sources) {
  const list = byId('sources');
  const fragment = document.createDocumentFragment();
  if (!sources.length) {
    const empty = document.createElement('li');
    empty.className = 'source-empty';
    empty.textContent = 'No source traffic recorded yet.';
    list.replaceChildren(empty);
    return;
  }
  const maxPackets = Math.max(1, ...sources.map(source => source.packets));
  for (const [index, source] of sources.entries()) {
    const row = document.createElement('li');
    row.className = 'source-row';
    const meter = document.createElement('div');
    meter.className = 'source-meter';
    const track = document.createElement('span');
    track.className = 'source-bar-track';
    track.setAttribute('aria-hidden', 'true');
    const fill = document.createElement('span');
    fill.className = 'source-fill';
    fill.style.width = `${Math.max(0, source.packets / maxPackets * 100)}%`;
    track.appendChild(fill);
    const address = document.createElement('span');
    address.className = 'source-address';
    address.textContent = source.src;
    address.title = source.src;
    const count = document.createElement('span');
    count.className = 'source-count';
    count.textContent = formatNumber(source.packets);
    row.setAttribute('aria-label', `Rank ${index + 1}, ${source.src}, ${formatNumber(source.packets)} packets`);
    meter.append(track, address, count);
    row.appendChild(meter);
    fragment.appendChild(row);
  }
  list.replaceChildren(fragment);
}

/* Status and health */
function setStatus(online) {
  byId('status').textContent = online ? 'LIVE' : 'OFFLINE / RETRYING';
  byId('led').className = online ? 'led live' : 'led offline';
}

function setRates(sample) {
  byId('pass-rate').textContent = sample ? formatNumber(sample.pass) : '—';
  byId('drop-rate').textContent = sample ? formatNumber(sample.drop) : '—';
}

function renderHealth(health) {
  const failures = Object.entries(health).filter(([key, value]) => {
    if (key === 'events_read') return false;
    return key === 'stream_error' ? Boolean(value) : Number(value) !== 0;
  });
  const summary = byId('health-summary');
  const strip = summary.closest('.strip-title');
  strip.classList.toggle('degraded', failures.length > 0);
  strip.classList.toggle('error', Boolean(health.stream_error));
  summary.textContent = failures.length
    ? `DEGRADED · ${failures.length} CHECK${failures.length === 1 ? '' : 'S'}`
    : 'ALL CHECKS NORMAL';
  byId('event-lost').textContent = formatNumber(health.event_lost);
  byId('event-lost').closest('.detail-metric').classList.toggle('alert', Number(health.event_lost) > 0);
  const warning = byId('warning');
  warning.hidden = failures.length === 0;
  warning.textContent = failures.length
    ? 'Telemetry degraded: ' + failures.map(([key, value]) => `${key}=${value}`).join(' · ')
    : '';
}

/* Snapshot rendering */
function renderCounters(stats) {
  for (const key of ['bounced', 'honeypotted', 'malformed', 'other', 'jailed']) {
    byId(key).textContent = formatNumber(stats[key]);
  }
  byId('default-hits').textContent = formatNumber(stats.default_hits);
  byId('generation').textContent = `POLICY v${stats.rules_version}`;
  byId('jail-count').textContent = `${formatNumber(stats.jailed_sources)} JAILED`;
  byId('sets').textContent = stats.sets.map(set => `${set.name} (${set.prefixes})`).join(' · ') || 'NONE';
}

function renderRules(rules) {
  const maxHits = Math.max(1, ...rules.map(rule => rule.hits));
  renderTable('rules', rules, [
    {value: rule => rule.line},
    {value: rule => activityCell(rule, maxHits)},
    {value: rule => formatNumber(rule.passed)},
    {value: rule => formatNumber(rule.dropped)},
    {value: rule => formatNumber(rule.bounced)},
    {value: rule => formatNumber(rule.honeypotted)}
  ], 'No rules configured — fragment/default policy applies.');
}

function renderJail(entries) {
  renderTable('jail', entries, [
    {value: entry => entry.src},
    {value: entry => `${formatNumber(entry.seconds_left)} sec`}
  ], 'No sources jailed.');
}

function renderEvents(events) {
  renderTable('events', events.slice(-20), [
    {value: event => event.line},
    {value: event => verdictBadge(event)},
    {value: event => event.src},
    {value: event => event.dst},
    {value: event => event.proto},
    {value: event => event.sport},
    {value: event => event.dport}
  ], 'No logged rule decisions yet.');
}

/* Polling */
function updateRates(stats, now) {
  const monotonic = previousSample && stats.passed >= previousSample.passed && stats.dropped >= previousSample.dropped;
  const elapsed = previousSample ? (now - previousSample.time) / 1000 : 0;
  if (monotonic && elapsed > 0) {
    history.push({
      pass: Math.round((stats.passed - previousSample.passed) / elapsed),
      drop: Math.round((stats.dropped - previousSample.dropped) / elapsed)
    });
    if (history.length > sampleLimit) history.shift();
  } else if (previousSample) {
    // Counters reset/decreased: rebase instead of drawing a misleading spike.
    history = [];
  }
  previousSample = {time: now, passed: stats.passed, dropped: stats.dropped};
  setRates(history.at(-1));
  renderChart();
}

async function update() {
  if (inFlight) return;
  inFlight = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 900);
  try {
    const [stats, jail, events, health] = await Promise.all(endpoints.map(async path => {
      const response = await fetch(path, {cache: 'no-store', signal: controller.signal});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    }));

    updateRates(stats, performance.now());
    renderCounters(stats);
    renderRules(stats.rules);
    renderSources(stats.top_sources);
    renderJail(jail);
    renderEvents(events);
    renderHealth(health);
    setStatus(true);
  } catch (_) {
    // Require two good samples after a gap before displaying a new rate.
    previousSample = null;
    history = [];
    renderChart();
    setRates(null);
    setStatus(false);
  } finally {
    clearTimeout(timeout);
    inFlight = false;
  }
}

/* Boot */
for (const option of chartOptions) {
  option.addEventListener('click', () => {
    if (option.dataset.chart === chartMode) return;
    chartMode = option.dataset.chart;
    updateChartMode();
    renderChart();
  });
}
updateChartMode();
renderChart();
update();
setInterval(update, 1000);
