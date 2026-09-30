const test = require('node:test');
const assert = require('node:assert/strict');
const SlidingWindowTracker = require('../src/engine/slidingWindow');
const DetectionEngine = require('../src/engine/detectionEngine');
const { parseLogLine } = require('../src/parser/logParser');

test('SIEM Detection Engine - Sliding Window', async (t) => {
  await t.test('accurately records and counts events within specific time window', () => {
    const tracker = new SlidingWindowTracker({ autoPrune: false });
    const now = 1700000000000;
    const ip = '192.0.2.1';

    tracker.record(ip, 'TEST_EVENT', now - 10000, { step: 1 });
    tracker.record(ip, 'TEST_EVENT', now - 5000, { step: 2 });
    tracker.record(ip, 'TEST_EVENT', now - 1000, { step: 3 });
    // Event outside 20s window
    tracker.record(ip, 'TEST_EVENT', now - 25000, { step: 0 });

    const countIn20s = tracker.count(ip, 'TEST_EVENT', 20000, now);
    assert.equal(countIn20s, 3);

    const countIn6s = tracker.count(ip, 'TEST_EVENT', 6000, now);
    assert.equal(countIn6s, 2);
  });
});

test('SIEM Detection Engine - RULE-001: SSH Brute Force', async (t) => {
  await t.test('triggers High severity alert on 5th failed password within 60s from same IP', () => {
    const engine = new DetectionEngine({ cooldownMs: 0 });
    const ip = '198.51.100.42';
    const now = Date.now();

    let alerts = [];
    for (let i = 0; i < 4; i++) {
      const event = {
        type: 'auth_log',
        authStatus: 'FAILED',
        message: `Failed password for invalid user user${i} from ${ip}`,
        ip,
        timestamp: new Date(now + i * 1000).toISOString()
      };
      alerts = engine.processEvent(event);
      assert.equal(alerts.length, 0, `Should not alert on attempt ${i + 1}`);
    }

    // 5th attempt
    const fifthEvent = {
      type: 'auth_log',
      authStatus: 'FAILED',
      message: `Failed password for root from ${ip}`,
      ip,
      timestamp: new Date(now + 4000).toISOString()
    };
    alerts = engine.processEvent(fifthEvent);
    
    assert.equal(alerts.length, 1, 'Should trigger alert on 5th attempt');
    assert.equal(alerts[0].ruleId, 'RULE-001');
    assert.equal(alerts[0].severity, 'High');
    assert.equal(alerts[0].attackerIp, ip);
    assert.ok(alerts[0].mitigation.includes('iptables'));
  });

  await t.test('does NOT trigger alert if attempts are distributed beyond 60s window (false-positive prevention)', () => {
    const tracker = new SlidingWindowTracker({ autoPrune: false });
    const engine = new DetectionEngine({ tracker, cooldownMs: 0 });
    const ip = '198.51.100.99';
    const baseTime = 1700000000000;

    // 4 attempts spread over 2 minutes (30s apart)
    for (let i = 0; i < 4; i++) {
      const event = {
        type: 'auth_log',
        authStatus: 'FAILED',
        message: `Failed password for user from ${ip}`,
        ip,
        timestamp: new Date(baseTime + i * 30000).toISOString()
      };
      const alerts = engine.processEvent(event);
      assert.equal(alerts.length, 0);
    }
  });
});

test('SIEM Detection Engine - RULE-002: Directory Traversal & Fuzzing', async (t) => {
  await t.test('detects path traversal sequences (../, win.ini, /etc/passwd)', () => {
    const engine = new DetectionEngine({ cooldownMs: 0 });
    const log1 = parseLogLine('185.220.101.5 - - [30/Sep/2026:14:05:01 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 403 512 "-" "DirBuster"');
    
    const alerts = engine.processEvent(log1);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].ruleId, 'RULE-002');
    assert.equal(alerts[0].severity, 'Medium');
    assert.equal(alerts[0].attackerIp, '185.220.101.5');
  });

  await t.test('detects web endpoint fuzzing with >10 404 responses in 30s', () => {
    const engine = new DetectionEngine({ cooldownMs: 0 });
    const ip = '194.26.29.112';
    const now = Date.now();

    for (let i = 1; i <= 10; i++) {
      const log = {
        type: 'access_log',
        method: 'GET',
        path: `/nonexistent-${i}`,
        statusCode: 404,
        ip,
        timestamp: new Date(now + i * 500).toISOString()
      };
      const alerts = engine.processEvent(log);
      assert.equal(alerts.length, 0, `Should not alert on 404 count ${i}`);
    }

    // 11th 404
    const eleventhLog = {
      type: 'access_log',
      method: 'GET',
      path: '/nonexistent-11',
      statusCode: 404,
      ip,
      timestamp: new Date(now + 6000).toISOString()
    };
    const alerts = engine.processEvent(eleventhLog);
    assert.equal(alerts.length, 1, 'Should trigger fuzzing alert on >10 404s in 30s');
    assert.equal(alerts[0].ruleId, 'RULE-002');
    assert.equal(alerts[0].attackerIp, ip);
  });
});

test('SIEM Detection Engine - RULE-003: SQL Injection Signature', async (t) => {
  await t.test('detects UNION SELECT injection attempt', () => {
    const engine = new DetectionEngine({ cooldownMs: 0 });
    const raw = '203.0.113.88 - - [30/Sep/2026:14:06:11 +0000] "GET /products/search?query=test%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 200 4890 "-" "Sqlmap"';
    const parsed = parseLogLine(raw);

    const alerts = engine.processEvent(parsed);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].ruleId, 'RULE-003');
    assert.equal(alerts[0].severity, 'High');
    assert.ok(alerts[0].description.includes('SQL injection'));
  });

  await t.test('detects OR 1=1 bypass payload', () => {
    const engine = new DetectionEngine({ cooldownMs: 0 });
    const raw = '203.0.113.88 - - [30/Sep/2026:14:06:10 +0000] "GET /api/v1/users?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 3420 "-" "Mozilla"';
    const parsed = parseLogLine(raw);

    const alerts = engine.processEvent(parsed);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].ruleId, 'RULE-003');
  });
});

test('SIEM Detection Engine - RULE-004: High-Frequency Request Burst', async (t) => {
  await t.test('triggers alert when request count exceeds 50 in 10s', () => {
    const engine = new DetectionEngine({ cooldownMs: 0 });
    const ip = '45.33.32.156';
    const now = Date.now();

    for (let i = 1; i <= 50; i++) {
      const log = {
        type: 'access_log',
        method: 'GET',
        path: `/page/${i}`,
        statusCode: 200,
        ip,
        timestamp: new Date(now + i * 50).toISOString()
      };
      const alerts = engine.processEvent(log);
      assert.equal(alerts.length, 0);
    }

    // 51st request
    const burstLog = {
      type: 'access_log',
      method: 'GET',
      path: '/page/51',
      statusCode: 200,
      ip,
      timestamp: new Date(now + 2600).toISOString()
    };
    const alerts = engine.processEvent(burstLog);
    assert.equal(alerts.length, 1, 'Should trigger rate limit alert on >50 requests');
    assert.equal(alerts[0].ruleId, 'RULE-004');
    assert.equal(alerts[0].severity, 'Low');
  });
});
