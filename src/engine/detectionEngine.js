/**
 * SentinelLog SIEM Real-Time Detection Engine
 * Evaluates streaming events against correlation rules using sliding-window heuristics and signatures.
 */

const SlidingWindowTracker = require('./slidingWindow');

function safeUrlDecode(str) {
  if (!str) return '';
  try {
    let decoded = str.replace(/\+/g, ' ');
    decoded = decodeURIComponent(decoded);
    try {
      decoded = decodeURIComponent(decoded);
    } catch {}
    return decoded;
  } catch {
    return str;
  }
}

// SQL Injection Signature Regex (Case-insensitive)
const SQLI_PATTERNS = [
  /(?:\bunion\s+(?:all\s+)?select\b)/i,
  /(?:(?:'|"|%27|%22)?\s*or\s+(?:'|"|%27|%22)?1(?:'|"|%27|%22)?\s*=\s*(?:'|"|%27|%22)?1|\bor\s+1\s*=\s*1\b|\b1\s*=\s*1\b)/i,
  /(?:;\s*drop\s+table|;\s*shutdown|;\s*exec\s*\(|;\s*declare\s*@)/i,
  /(?:\binformation_schema\.(?:tables|columns|schemata)\b)/i,
  /(?:\bsleep\(\s*\d+\s*\)|\bbenchmark\(\s*\d+\s*,\s*.*\)|waitfor\s+delay\s+['"])/i,
  /(?:'\s*--|"\s*--|--|\/\*|\*\/|\bOR\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?)/i,
  /(?:load_file\(|into\s+(?:outfile|dumpfile))/i
];

// Directory Traversal Signatures
const TRAVERSAL_PATTERNS = [
  /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e%252f)/i,
  /(?:\/etc\/(?:passwd|shadow|hosts|group|sudoers))/i,
  /(?:c:\\(?:windows|winnt)\\(?:system32|win\.ini|system\.ini)|win\.ini|boot\.ini)/i,
  /(?:\/proc\/self\/(?:environ|status|cmdline))/i
];

class DetectionEngine {
  constructor(options = {}) {
    this.tracker = options.tracker || new SlidingWindowTracker();
    this.alerts = [];
    this.maxStoredAlerts = options.maxStoredAlerts || 500;
    // Cooldown tracker to prevent alert storms for continuous attacks from same IP
    this.alertCooldowns = new Map(); // key: `ruleId:ip` -> lastAlertTimestamp
    this.cooldownMs = options.cooldownMs || 15000; // 15s cooldown per rule per IP
    
    // Listeners for alert emissions
    this.alertListeners = [];
  }

  /**
   * Register a listener for new alerts.
   * @param {Function} callback 
   */
  onAlert(callback) {
    if (typeof callback === 'function') {
      this.alertListeners.push(callback);
    }
  }

  /**
   * Emit an alert to all registered listeners.
   * @param {object} alert 
   */
  emitAlert(alert) {
    this.alerts.unshift(alert);
    if (this.alerts.length > this.maxStoredAlerts) {
      this.alerts.pop();
    }
    for (const listener of this.alertListeners) {
      try {
        listener(alert);
      } catch (err) {
        console.error('Alert listener error:', err);
      }
    }
  }

  /**
   * Check cooldown for an IP and rule.
   * @param {string} ruleId 
   * @param {string} ip 
   * @param {number} timestamp 
   * @returns {boolean} True if allowed to fire, False if on cooldown
   */
  checkCooldown(ruleId, ip, timestamp) {
    const key = `${ruleId}:${ip}`;
    const lastTime = this.alertCooldowns.get(key) || 0;
    if (timestamp - lastTime >= this.cooldownMs) {
      this.alertCooldowns.set(key, timestamp);
      return true;
    }
    return false;
  }

  /**
   * Generate a unique Alert ID.
   * @returns {string}
   */
  generateAlertId() {
    return `ALT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
  }

  /**
   * Process a single parsed log event and evaluate correlation rules.
   * @param {object} log 
   * @returns {Array<object>} Triggered alerts
   */
  processEvent(log) {
    if (!log) return [];
    const triggeredAlerts = [];
    const eventTime = log.timestamp ? new Date(log.timestamp).getTime() : Date.now();
    const ts = isNaN(eventTime) ? Date.now() : eventTime;
    const ip = log.ip || '0.0.0.0';

    // 1. Sliding window registration
    this.tracker.record(ip, 'ALL_REQUESTS', ts, log);

    // ==========================================
    // RULE-001 [High]: SSH Brute Force
    // 5 or more failed login attempts from a single IP within 60s.
    // ==========================================
    if (log.type === 'auth_log' && (log.authStatus === 'FAILED' || /Failed password|authentication failure/i.test(log.message || ''))) {
      this.tracker.record(ip, 'SSH_FAILED', ts, log);
      const failedEvents = this.tracker.getEvents(ip, 'SSH_FAILED', 60000, ts);

      if (failedEvents.length >= 5) {
        if (this.checkCooldown('RULE-001', ip, ts)) {
          const evidenceLogs = failedEvents.slice(-5).map(e => e.data.raw || JSON.stringify(e.data));
          const alert = {
            id: this.generateAlertId(),
            ruleId: 'RULE-001',
            ruleName: 'SSH Brute Force Attack',
            severity: 'High',
            attackerIp: ip,
            target: log.host ? `${log.host} (user: ${log.user || 'multiple'})` : (log.user || 'SSH Daemon'),
            timestamp: new Date(ts).toISOString(),
            mitreTechnique: 'T1110.001 - Brute Force: Password Guessing',
            description: `${failedEvents.length} failed SSH authentication attempts detected from ${ip} within 60 seconds.`,
            count: failedEvents.length,
            evidence: evidenceLogs,
            mitigation: `Execute firewall isolation: iptables -A INPUT -s ${ip} -p tcp --dport 22 -j DROP\nOr append to fail2ban jail: fail2ban-client set sshd banip ${ip}`,
            status: 'Active'
          };
          this.emitAlert(alert);
          triggeredAlerts.push(alert);
        }
      }
    }

    // ==========================================
    // RULE-002 [Medium]: Directory Traversal & Fuzzing
    // Requests containing '../', 'win.ini', '/etc/passwd', OR >10 404 responses in 30s.
    // ==========================================
    if (log.type === 'access_log') {
      const decodedPath = decodeURIComponent(log.path || '');
      let hasTraversalSignature = false;
      let matchedSignature = '';

      for (const pattern of TRAVERSAL_PATTERNS) {
        if (pattern.test(log.path || '') || pattern.test(decodedPath) || pattern.test(log.raw || '')) {
          hasTraversalSignature = true;
          matchedSignature = pattern.toString();
          break;
        }
      }

      if (hasTraversalSignature) {
        if (this.checkCooldown('RULE-002-SIG', ip, ts)) {
          const alert = {
            id: this.generateAlertId(),
            ruleId: 'RULE-002',
            ruleName: 'Directory Traversal & Path Manipulation',
            severity: 'Medium',
            attackerIp: ip,
            target: log.path || 'Web Server Endpoint',
            timestamp: new Date(ts).toISOString(),
            mitreTechnique: 'T1083 - File and Directory Discovery',
            description: `Directory traversal attack pattern detected targeting path "${log.path}" from origin ${ip}.`,
            count: 1,
            evidence: [log.raw || `HTTP ${log.method} ${log.path}`],
            mitigation: `Sanitize URL path resolution on backend. Add immediate WAF filter or drop rule: ufw deny from ${ip}`,
            status: 'Active'
          };
          this.emitAlert(alert);
          triggeredAlerts.push(alert);
        }
      }

      // Track 404 Fuzzing in sliding window
      if (log.statusCode === 404) {
        this.tracker.record(ip, 'HTTP_404', ts, log);
        const notFoundEvents = this.tracker.getEvents(ip, 'HTTP_404', 30000, ts);

        if (notFoundEvents.length > 10) {
          if (this.checkCooldown('RULE-002-FUZZ', ip, ts)) {
            const evidenceLogs = notFoundEvents.slice(-5).map(e => e.data.raw || JSON.stringify(e.data));
            const alert = {
              id: this.generateAlertId(),
              ruleId: 'RULE-002',
              ruleName: 'Web Endpoint Fuzzing / Discovery',
              severity: 'Medium',
              attackerIp: ip,
              target: 'Web Application Endpoints',
              timestamp: new Date(ts).toISOString(),
              mitreTechnique: 'T1190 - Exploit Public-Facing Application (Fuzzing)',
              description: `High volume of 404 Not Found responses (${notFoundEvents.length} in 30s) from ${ip} indicates active directory fuzzing.`,
              count: notFoundEvents.length,
              evidence: evidenceLogs,
              mitigation: `Rate limit or temporarily block ${ip} at reverse proxy / load balancer (Nginx/Cloudflare).`,
              status: 'Active'
            };
            this.emitAlert(alert);
            triggeredAlerts.push(alert);
          }
        }
      }
    }

    // ==========================================
    // RULE-003 [High]: SQL Injection Signature
    // Queries containing common SQLi patterns ('UNION SELECT', '' OR 1=1', '--', etc.)
    // ==========================================
    if (log.type === 'access_log') {
      const inspectRaw = `${log.path || ''} ${log.referer || ''} ${log.raw || ''}`;
      const inspectDecoded = safeUrlDecode(inspectRaw);
      let isSqli = false;
      let matchedPattern = '';

      for (const pattern of SQLI_PATTERNS) {
        if (pattern.test(inspectRaw) || pattern.test(inspectDecoded)) {
          isSqli = true;
          matchedPattern = pattern.toString();
          break;
        }
      }

      if (isSqli) {
        if (this.checkCooldown('RULE-003', ip, ts)) {
          const alert = {
            id: this.generateAlertId(),
            ruleId: 'RULE-003',
            ruleName: 'SQL Injection Signature Detected',
            severity: 'High',
            attackerIp: ip,
            target: log.path || 'Database-Backed Endpoint',
            timestamp: new Date(ts).toISOString(),
            mitreTechnique: 'T1190 - Exploit Public-Facing Application: SQL Injection',
            description: `SQL injection payload identified in HTTP request from ${ip} targeting endpoint ${log.path}.`,
            count: 1,
            evidence: [log.raw || `HTTP ${log.method} ${log.path}`],
            mitigation: `Verify parameterized queries / ORM prepared statements for ${log.path}. Apply WAF rule to block SQL injection payloads from ${ip}.`,
            status: 'Active'
          };
          this.emitAlert(alert);
          triggeredAlerts.push(alert);
        }
      }
    }

    // ==========================================
    // RULE-004 [Low/Info]: High-Frequency Request Burst
    // More than 50 requests in 10 seconds from one origin IP.
    // ==========================================
    const recentRequests = this.tracker.getEvents(ip, 'ALL_REQUESTS', 10000, ts);
    if (recentRequests.length > 50) {
      if (this.checkCooldown('RULE-004', ip, ts)) {
        const evidenceLogs = recentRequests.slice(-5).map(e => e.data.raw || JSON.stringify(e.data));
        const alert = {
          id: this.generateAlertId(),
          ruleId: 'RULE-004',
          ruleName: 'High-Frequency Request Burst (DDoS/Scraper)',
          severity: 'Low',
          attackerIp: ip,
          target: 'Web Infrastructure',
          timestamp: new Date(ts).toISOString(),
          mitreTechnique: 'T1498 - Network Denial of Service: Direct Volume',
          description: `Rapid request burst of ${recentRequests.length} requests in 10s detected from IP ${ip}.`,
          count: recentRequests.length,
          evidence: evidenceLogs,
          mitigation: `Enforce per-IP token bucket rate limiting (e.g. limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s in Nginx).`,
          status: 'Active'
        };
        this.emitAlert(alert);
        triggeredAlerts.push(alert);
      }
    }

    return triggeredAlerts;
  }

  /**
   * Process a batch of logs in sequence.
   * @param {Array<object>} logs 
   * @returns {Array<object>} Triggered alerts
   */
  processBatch(logs) {
    const allAlerts = [];
    for (const log of logs) {
      const alerts = this.processEvent(log);
      allAlerts.push(...alerts);
    }
    return allAlerts;
  }

  /**
   * Get all recorded alerts.
   * @param {object} filters 
   * @returns {Array<object>}
   */
  getAlerts(filters = {}) {
    let list = [...this.alerts];
    if (filters.severity) {
      list = list.filter(a => a.severity.toLowerCase() === filters.severity.toLowerCase());
    }
    if (filters.ruleId) {
      list = list.filter(a => a.ruleId.toLowerCase() === filters.ruleId.toLowerCase());
    }
    if (filters.ip) {
      list = list.filter(a => a.attackerIp.includes(filters.ip));
    }
    const limit = filters.limit ? parseInt(filters.limit, 10) : 100;
    return list.slice(0, limit);
  }

  /**
   * Clear all stored alerts and tracker state.
   */
  reset() {
    this.alerts = [];
    this.alertCooldowns.clear();
    this.tracker.reset();
  }
}

module.exports = DetectionEngine;
