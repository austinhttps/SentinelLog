const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { app, server } = require('../server');

let baseUrl;

test.before((t, done) => {
  server.listen(0, () => {
    const port = server.address().port;
    baseUrl = `http://localhost:${port}/api`;
    done();
  });
});

test.after((t, done) => {
  server.close(done);
});

test('API Endpoints - Integration Tests', async (t) => {
  await t.test('POST /api/logs/ingest accepts raw log strings', async () => {
    const rawLogs = '192.168.1.1 - - [30/Sep/2026:14:20:10 +0000] "GET /test HTTP/1.1" 200 100 "-" "-"';
    const response = await fetch(`${baseUrl}/logs/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logs: rawLogs })
    });

    const data = await response.json();
    assert.equal(response.status, 200);
    assert.equal(data.success, true);
    assert.equal(data.totalLines, 1);
    assert.equal(data.parsedCount, 1);
  });

  await t.test('GET /api/metrics returns aggregated telemetry', async () => {
    const response = await fetch(`${baseUrl}/metrics`);
    const data = await response.json();

    assert.equal(response.status, 200);
    assert.equal(data.success, true);
    assert.ok(typeof data.metrics.totalEvents === 'number');
    assert.ok(Array.isArray(data.metrics.topAttackers));
  });

  await t.test('GET /api/scenarios returns attack presets', async () => {
    const response = await fetch(`${baseUrl}/scenarios`);
    const data = await response.json();

    assert.equal(response.status, 200);
    assert.equal(data.success, true);
    assert.ok(data.scenarios.length >= 5);
  });

  await t.test('POST /api/simulate initiates simulation', async () => {
    const response = await fetch(`${baseUrl}/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: 'ssh-brute-force' })
    });

    const data = await response.json();
    assert.equal(response.status, 200);
    assert.equal(data.success, true);
    assert.equal(data.scenario, 'ssh-brute-force');
  });

  await t.test('GET /api/alerts returns alert array', async () => {
    const response = await fetch(`${baseUrl}/alerts`);
    const data = await response.json();

    assert.equal(response.status, 200);
    assert.equal(data.success, true);
    assert.ok(Array.isArray(data.alerts));
  });

  await t.test('GET /api/samples/:filename returns raw sample text', async () => {
    const response = await fetch(`${baseUrl}/samples/access.log`);
    const text = await response.text();

    assert.equal(response.status, 200);
    assert.ok(text.includes('185.220.101.5'));
  });

  await t.test('POST /api/samples/load/access.log dynamically ingests access sample', async () => {
    const response = await fetch(`${baseUrl}/samples/load/access.log`, { method: 'POST' });
    const data = await response.json();

    assert.equal(response.status, 200);
    assert.equal(data.success, true);
    assert.ok(data.totalLines > 0);
    assert.ok(data.alertsTriggered > 0, 'Should trigger SIEM alerts from access.log attacks');
  });

  await t.test('POST /api/samples/load/mixed_attacks.log dynamically ingests multi-vector sample', async () => {
    const response = await fetch(`${baseUrl}/samples/load/mixed_attacks.log`, { method: 'POST' });
    const data = await response.json();

    assert.equal(response.status, 200);
    assert.equal(data.success, true);
    assert.ok(data.totalLines > 0);
    assert.ok(data.alertsTriggered > 0, 'Should trigger SIEM alerts from mixed_attacks.log');
  });
});
