/**
 * SentinelLog Log Parser Engine
 * Handles Apache/Nginx Combined Access Logs and Linux Syslog/Auth Logs
 * with resilient error recovery and zero uncaught exceptions.
 */

// Regex for Apache/Nginx Combined & Common Access Logs
// Supports unencoded queries with spaces, HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3, and optional referer/UA
const APACHE_NGINX_REGEX = /^(\S+)\s+(\S+)\s+(\S+)\s+\[([\w:/]+\s[+\-]\d{4})\]\s+"(?:([A-Za-z]+)\s+(.+?)(?:\s+HTTP\/([0-9.]+))?|-)"\s+(\d{3})\s+(\d+|-)(?:\s+"(.*?)"\s+"(.*?)")?/;

// Regex for Linux Syslog / Auth Log format
// E.g.: Sep 30 14:20:10 server1 sshd[12345]: Failed password for invalid user admin from 198.51.100.42 port 54321 ssh2
// E.g.: Sep 30 14:20:10 server1 sshd[12345]: Accepted password for austin from 10.0.0.15 port 49152 ssh2
// E.g.: 2026-09-30T14:20:10.123456+00:00 server1 sshd[12345]: ... (ISO syslog)
const SYSLOG_AUTH_REGEX = /^(?:([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+\-]\d{2}:\d{2}|Z)?))\s+([\w\-.]+)\s+([a-zA-Z0-9_\-\.\/]+)(?:\[(\d+)\])?:\s+(.*)$/;

const SSHD_FAILED_PATTERN = /(?:Failed password for(?: invalid user)?|authentication failure;.*rhost=)\s*([^\s]+)?.*from\s+([0-9a-fA-F\.\:]+)(?:\s+port\s+(\d+))?/i;
const SSHD_ACCEPTED_PATTERN = /Accepted (?:password|publickey) for\s+([^\s]+)\s+from\s+([0-9a-fA-F\.\:]+)(?:\s+port\s+(\d+))?/i;
const SSHD_INVALID_USER_PATTERN = /Invalid user\s+([^\s]+)\s+from\s+([0-9a-fA-F\.\:]+)/i;

/**
 * Parse an Apache or Nginx Combined Log line.
 * @param {string} line 
 * @returns {object|null}
 */
function parseAccessLog(line) {
  try {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return null;

    const match = trimmed.match(APACHE_NGINX_REGEX);
    if (!match) return null;

    const [
      ,
      ip,
      identity,
      user,
      rawTime,
      method = 'UNKNOWN',
      path = '/',
      httpVersion = '1.1',
      status,
      bytes,
      referer = '-',
      userAgent = '-'
    ] = match;

    let timestamp;
    try {
      // e.g. "30/Sep/2026:14:20:10 +0000"
      const dateParts = rawTime.match(/^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+\-]\d{4})$/);
      if (dateParts) {
        const monthMap = { Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06', Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12' };
        const day = dateParts[1].padStart(2, '0');
        const isoStr = `${dateParts[3]}-${monthMap[dateParts[2]] || '01'}-${day}T${dateParts[4]}:${dateParts[5]}:${dateParts[6]}${dateParts[7].slice(0, 3)}:${dateParts[7].slice(3)}`;
        const parsedDate = new Date(isoStr);
        timestamp = isNaN(parsedDate.getTime()) ? new Date().toISOString() : parsedDate.toISOString();
      } else {
        timestamp = new Date().toISOString();
      }
    } catch {
      timestamp = new Date().toISOString();
    }

    return {
      type: 'access_log',
      ip,
      identity: identity === '-' ? null : identity,
      user: user === '-' ? null : user,
      timestamp,
      method: method.toUpperCase(),
      path,
      httpVersion,
      statusCode: parseInt(status, 10),
      bytes: bytes === '-' ? 0 : parseInt(bytes, 10),
      referer: referer === '-' ? '' : referer,
      userAgent: userAgent === '-' ? '' : userAgent,
      raw: trimmed
    };
  } catch (err) {
    return {
      type: 'malformed',
      error: err.message,
      raw: line
    };
  }
}

/**
 * Parse a Linux Syslog / Auth Log line.
 * @param {string} line 
 * @returns {object|null}
 */
function parseSyslog(line) {
  try {
    const trimmed = line.trim();
    if (!trimmed) return null;

    const match = trimmed.match(SYSLOG_AUTH_REGEX);
    if (!match) return null;

    const [, bsdTime, isoTime, host, daemon, pidStr, message] = match;
    const pid = pidStr ? parseInt(pidStr, 10) : null;

    let timestamp;
    if (isoTime) {
      timestamp = new Date(isoTime).toISOString();
    } else if (bsdTime) {
      // e.g. "Sep 30 14:20:10" -> attach current year
      const currentYear = new Date().getFullYear();
      const parsedDate = new Date(`${bsdTime} ${currentYear}`);
      timestamp = isNaN(parsedDate.getTime()) ? new Date().toISOString() : parsedDate.toISOString();
    } else {
      timestamp = new Date().toISOString();
    }

    let authStatus = 'INFO';
    let user = null;
    let ip = null;
    let port = null;

    const failedMatch = message.match(SSHD_FAILED_PATTERN);
    const acceptedMatch = message.match(SSHD_ACCEPTED_PATTERN);
    const invalidMatch = message.match(SSHD_INVALID_USER_PATTERN);

    if (failedMatch) {
      authStatus = 'FAILED';
      user = failedMatch[1] || 'unknown';
      ip = failedMatch[2];
      port = failedMatch[3] ? parseInt(failedMatch[3], 10) : null;
    } else if (acceptedMatch) {
      authStatus = 'ACCEPTED';
      user = acceptedMatch[1];
      ip = acceptedMatch[2];
      port = acceptedMatch[3] ? parseInt(acceptedMatch[3], 10) : null;
    } else if (invalidMatch) {
      authStatus = 'FAILED';
      user = invalidMatch[1];
      ip = invalidMatch[2];
    } else {
      // Try to find any IP in the message if present
      const ipMatch = message.match(/(?:from|rhost=|client\s+)([0-9a-fA-F\.\:]+)/i);
      if (ipMatch) {
        ip = ipMatch[1];
      }
    }

    return {
      type: 'auth_log',
      timestamp,
      host,
      daemon,
      pid,
      message,
      authStatus,
      user,
      ip: ip || '127.0.0.1',
      port,
      raw: trimmed
    };
  } catch (err) {
    return {
      type: 'malformed',
      error: err.message,
      raw: line
    };
  }
}

/**
 * Universal Log Parser with automatic format detection and fallback.
 * Guarantees no uncaught exceptions.
 * @param {string} line 
 * @returns {object}
 */
function parseLogLine(line) {
  if (!line || typeof line !== 'string') {
    return {
      parsed: false,
      type: 'empty',
      error: 'Empty or non-string input',
      raw: String(line || '')
    };
  }

  const trimmed = line.trim();
  if (!trimmed) {
    return {
      parsed: false,
      type: 'empty',
      error: 'Empty line',
      raw: line
    };
  }

  // Handle comment lines
  if (trimmed.startsWith('#')) {
    return {
      parsed: true,
      type: 'comment',
      timestamp: new Date().toISOString(),
      message: trimmed,
      raw: trimmed
    };
  }

  try {
    // 1. Try Apache/Nginx format
    const accessLog = parseAccessLog(trimmed);
    if (accessLog && accessLog.type !== 'malformed') {
      return {
        parsed: true,
        ...accessLog
      };
    }

    // 2. Try Linux Syslog/Auth log format
    const syslog = parseSyslog(trimmed);
    if (syslog && syslog.type !== 'malformed') {
      return {
        parsed: true,
        ...syslog
      };
    }

    // 3. Fallback: Generic line with potential IP detection
    const genericIpMatch = trimmed.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    return {
      parsed: false,
      type: 'unstructured',
      timestamp: new Date().toISOString(),
      ip: genericIpMatch ? genericIpMatch[0] : '0.0.0.0',
      message: trimmed,
      raw: trimmed,
      warning: 'Could not strictly match standard access.log or syslog format'
    };
  } catch (err) {
    return {
      parsed: false,
      type: 'malformed',
      error: err.message,
      timestamp: new Date().toISOString(),
      raw: trimmed
    };
  }
}

/**
 * Parse a multi-line raw log string into an array of parsed log objects.
 * @param {string} text 
 * @returns {Array<object>}
 */
function parseBatchLogs(text) {
  if (!text || typeof text !== 'string') return [];
  const lines = text.split(/\r?\n/);
  const results = [];

  for (const line of lines) {
    if (!line.trim()) continue;
    results.push(parseLogLine(line));
  }

  return results;
}

module.exports = {
  parseAccessLog,
  parseSyslog,
  parseLogLine,
  parseBatchLogs
};
