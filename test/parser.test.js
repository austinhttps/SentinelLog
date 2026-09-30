const test = require('node:test');
const assert = require('node:assert/strict');
const { parseAccessLog, parseSyslog, parseLogLine, parseBatchLogs } = require('../src/parser/logParser');

test('Log Parser - Apache/Nginx Combined Format', async (t) => {
  await t.test('correctly parses standard combined access log', () => {
    const raw = '192.168.1.50 - frank [30/Sep/2026:14:20:10 +0000] "GET /api/v1/users?id=1 HTTP/1.1" 200 4520 "https://example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"';
    const parsed = parseAccessLog(raw);

    assert.ok(parsed, 'Parsed object should not be null');
    assert.equal(parsed.type, 'access_log');
    assert.equal(parsed.ip, '192.168.1.50');
    assert.equal(parsed.user, 'frank');
    assert.equal(parsed.method, 'GET');
    assert.equal(parsed.path, '/api/v1/users?id=1');
    assert.equal(parsed.statusCode, 200);
    assert.equal(parsed.bytes, 4520);
    assert.equal(parsed.referer, 'https://example.com');
    assert.ok(parsed.userAgent.includes('Mozilla/5.0'));
  });

  await t.test('handles hyphen placeholders for user, referer, bytes', () => {
    const raw = '10.0.0.1 - - [30/Sep/2026:14:20:10 +0000] "POST /login HTTP/1.1" 401 - "-" "-"';
    const parsed = parseAccessLog(raw);

    assert.ok(parsed);
    assert.equal(parsed.ip, '10.0.0.1');
    assert.equal(parsed.user, null);
    assert.equal(parsed.statusCode, 401);
    assert.equal(parsed.bytes, 0);
  });
});

test('Log Parser - Linux Syslog / Auth Format', async (t) => {
  await t.test('correctly parses SSH failed password attempt', () => {
    const raw = 'Sep 30 14:20:10 sec-srv-01 sshd[12345]: Failed password for invalid user admin from 198.51.100.42 port 54321 ssh2';
    const parsed = parseSyslog(raw);

    assert.ok(parsed);
    assert.equal(parsed.type, 'auth_log');
    assert.equal(parsed.host, 'sec-srv-01');
    assert.equal(parsed.daemon, 'sshd');
    assert.equal(parsed.pid, 12345);
    assert.equal(parsed.authStatus, 'FAILED');
    assert.equal(parsed.user, 'admin');
    assert.equal(parsed.ip, '198.51.100.42');
    assert.equal(parsed.port, 54321);
  });

  await t.test('correctly parses SSH accepted login', () => {
    const raw = 'Sep 30 14:22:15 gateway sshd[8890]: Accepted password for austin from 10.0.0.15 port 49152 ssh2';
    const parsed = parseSyslog(raw);

    assert.ok(parsed);
    assert.equal(parsed.authStatus, 'ACCEPTED');
    assert.equal(parsed.user, 'austin');
    assert.equal(parsed.ip, '10.0.0.15');
  });

  await t.test('handles sudo command syslog line', () => {
    const raw = 'Sep 30 14:25:00 db01 sudo: austin : TTY=pts/0 ; PWD=/home/austin ; USER=root ; COMMAND=/bin/bash';
    const parsed = parseSyslog(raw);

    assert.ok(parsed);
    assert.equal(parsed.host, 'db01');
    assert.equal(parsed.daemon, 'sudo');
  });
});

test('Log Parser - Error Resilience & Malformed Input Handling', async (t) => {
  await t.test('safely rejects garbage string without throwing', () => {
    const raw = '+++INVALID RANDOM GARBAGE @@@ 123456789 ???';
    const parsed = parseLogLine(raw);

    assert.equal(parsed.parsed, false);
    assert.ok(parsed.raw.includes('INVALID RANDOM GARBAGE'));
  });

  await t.test('handles empty and null inputs safely', () => {
    assert.equal(parseLogLine('').parsed, false);
    assert.equal(parseLogLine(null).parsed, false);
    assert.equal(parseLogLine(undefined).parsed, false);
  });

  await t.test('batch parses mixed multiline string', () => {
    const multiline = `
      192.168.1.50 - - [30/Sep/2026:14:20:10 +0000] "GET /test HTTP/1.1" 200 100 "-" "-"
      Sep 30 14:20:10 sec-srv-01 sshd[12345]: Failed password for root from 198.51.100.42 port 54321 ssh2
      totally invalid log line here
    `;

    const results = parseBatchLogs(multiline);
    assert.equal(results.length, 3);
    assert.equal(results[0].parsed, true);
    assert.equal(results[1].parsed, true);
    assert.equal(results[2].parsed, false);
  });
});
