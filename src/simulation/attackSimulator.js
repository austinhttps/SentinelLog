/**
 * SentinelLog Attack Simulator
 * Injects pre-scripted cyber attack scenarios to demonstrate real-time SIEM alerting.
 */

class AttackSimulator {
  constructor(options = {}) {
    this.onEventCallback = options.onEvent || (() => {});
    this.activeSimulations = new Map();
  }

  /**
   * Set callback for generated log events.
   * @param {Function} cb 
   */
  setEventCallback(cb) {
    this.onEventCallback = cb;
  }

  /**
   * Get list of available attack simulation scenarios.
   */
  getScenarios() {
    return [
      {
        id: 'ssh-brute-force',
        name: 'SSH Brute Force Attack',
        targetRule: 'RULE-001',
        severity: 'High',
        description: 'Simulates 8 rapid failed password attempts against SSH daemon from 198.51.100.42 across 3 seconds.',
        attackerIp: '198.51.100.42',
        durationMs: 3000
      },
      {
        id: 'sql-injection',
        name: 'SQL Injection Exploitation',
        targetRule: 'RULE-003',
        severity: 'High',
        description: 'Injects UNION SELECT and authentication bypass payloads targeting /api/v1/auth and /products/view.',
        attackerIp: '203.0.113.88',
        durationMs: 2000
      },
      {
        id: 'directory-traversal',
        name: 'Directory Traversal / Arbitrary File Read',
        targetRule: 'RULE-002',
        severity: 'Medium',
        description: 'Sends requests attempting to read /etc/passwd and win.ini via path traversal sequences.',
        attackerIp: '185.220.101.5',
        durationMs: 2000
      },
      {
        id: 'endpoint-fuzzing',
        name: 'Directory Fuzzing / 404 Scanning',
        targetRule: 'RULE-002',
        severity: 'Medium',
        description: 'Fuzzes 14 non-existent admin and configuration endpoints in rapid succession triggering 404 threshold.',
        attackerIp: '194.26.29.112',
        durationMs: 2500
      },
      {
        id: 'ddos-burst',
        name: 'High-Frequency Request Flood',
        targetRule: 'RULE-004',
        severity: 'Low',
        description: 'Floods API with 60 rapid requests within 3 seconds to trigger volumetric rate-limit alert.',
        attackerIp: '45.33.32.156',
        durationMs: 3000
      },
      {
        id: 'multi-vector',
        name: 'Multi-Vector APT Assault (All Scenarios)',
        targetRule: 'RULE-001 - RULE-004',
        severity: 'Critical / Mixed',
        description: 'Coordinated multi-vector intrusion combining brute force, SQLi, traversal, and traffic flood.',
        attackerIp: 'Distributed (Multiple IPs)',
        durationMs: 6000
      }
    ];
  }

  /**
   * Run a simulation by scenario ID.
   * @param {string} scenarioId 
   * @returns {Promise<object>}
   */
  async runScenario(scenarioId = 'ssh-brute-force') {
    const simId = `SIM-${Date.now()}`;
    
    switch (scenarioId) {
      case 'ssh-brute-force':
        return this.runSshBruteForce(simId);
      case 'sql-injection':
        return this.runSqlInjection(simId);
      case 'directory-traversal':
        return this.runDirectoryTraversal(simId);
      case 'endpoint-fuzzing':
        return this.runEndpointFuzzing(simId);
      case 'ddos-burst':
        return this.runDdosBurst(simId);
      case 'multi-vector':
        return this.runMultiVector(simId);
      default:
        return this.runSshBruteForce(simId);
    }
  }

  /**
   * Helper to format syslog line with current time.
   */
  formatSyslog(host, daemon, pid, message) {
    const now = new Date();
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[now.getMonth()];
    const day = String(now.getDate()).padStart(2, ' ');
    const time = now.toTimeString().split(' ')[0];
    return `${month} ${day} ${time} ${host} ${daemon}[${pid}]: ${message}`;
  }

  /**
   * Helper to format access log line with current time.
   */
  formatAccessLog(ip, method, path, status, bytes = 1200, ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36') {
    const now = new Date();
    const day = String(now.getDate()).padStart(2, '0');
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[now.getMonth()];
    const year = now.getFullYear();
    const time = now.toTimeString().split(' ')[0];
    return `${ip} - - [${day}/${month}/${year}:${time} +0000] "${method} ${path} HTTP/1.1" ${status} ${bytes} "-" "${ua}"`;
  }

  /**
   * Delay helper
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * SSH Brute Force Scenario: 8 failed attempts across 3 seconds from 198.51.100.42
   */
  async runSshBruteForce(simId) {
    const ip = '198.51.100.42';
    const usernames = ['root', 'admin', 'ubuntu', 'oracle', 'postgres', 'deploy', 'system', 'root'];
    const logs = [];

    for (let i = 0; i < usernames.length; i++) {
      const port = 52000 + i;
      const user = usernames[i];
      const line = this.formatSyslog('sec-srv-01', 'sshd', 14200 + i, `Failed password for invalid user ${user} from ${ip} port ${port} ssh2`);
      logs.push(line);
      this.onEventCallback(line, { scenario: 'ssh-brute-force', step: i + 1, total: usernames.length });
      await this.sleep(300);
    }

    return { success: true, simId, scenario: 'ssh-brute-force', eventCount: logs.length, attackerIp: ip };
  }

  /**
   * SQL Injection Scenario
   */
  async runSqlInjection(simId) {
    const ip = '203.0.113.88';
    const payloads = [
      `GET /api/v1/users?id=1%27%20OR%20%271%27=%271`,
      `POST /api/v1/auth/login?username=admin'--&password=foo`,
      `GET /products/search?query=test%27%20UNION%20SELECT%20null,username,password%20FROM%20users--`,
      `GET /items?category=1;%20DROP%20TABLE%20temp_sessions;--`
    ];

    for (let i = 0; i < payloads.length; i++) {
      const [method, path] = payloads[i].split(' ');
      const line = this.formatAccessLog(ip, method, path, 200, 3420, 'Sqlmap/1.6.12#stable');
      this.onEventCallback(line, { scenario: 'sql-injection', step: i + 1, total: payloads.length });
      await this.sleep(400);
    }

    return { success: true, simId, scenario: 'sql-injection', eventCount: payloads.length, attackerIp: ip };
  }

  /**
   * Directory Traversal Scenario
   */
  async runDirectoryTraversal(simId) {
    const ip = '185.220.101.5';
    const paths = [
      '/static/../../../../etc/passwd',
      '/download?file=../../../../windows/win.ini',
      '/images/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow',
      '/files/view?path=../../boot.ini'
    ];

    for (let i = 0; i < paths.length; i++) {
      const line = this.formatAccessLog(ip, 'GET', paths[i], 403, 512, 'DirBuster-1.0-RC1');
      this.onEventCallback(line, { scenario: 'directory-traversal', step: i + 1, total: paths.length });
      await this.sleep(400);
    }

    return { success: true, simId, scenario: 'directory-traversal', eventCount: paths.length, attackerIp: ip };
  }

  /**
   * Endpoint Fuzzing Scenario: 14 consecutive 404s
   */
  async runEndpointFuzzing(simId) {
    const ip = '194.26.29.112';
    const paths = [
      '/admin.php', '/wp-admin/', '/.env', '/.git/config', '/phpmyadmin/',
      '/config.json', '/backup.zip', '/api/v2/secret', '/actuator/health',
      '/database.sql', '/server-status', '/elmah.axd', '/console/', '/shell.php'
    ];

    for (let i = 0; i < paths.length; i++) {
      const line = this.formatAccessLog(ip, 'GET', paths[i], 404, 280, 'ffuf/v2.0.0');
      this.onEventCallback(line, { scenario: 'endpoint-fuzzing', step: i + 1, total: paths.length });
      await this.sleep(150);
    }

    return { success: true, simId, scenario: 'endpoint-fuzzing', eventCount: paths.length, attackerIp: ip };
  }

  /**
   * DDoS Request Burst Scenario: 55 requests in 2 seconds
   */
  async runDdosBurst(simId) {
    const ip = '45.33.32.156';
    const total = 55;

    for (let i = 0; i < total; i++) {
      const line = this.formatAccessLog(ip, 'GET', `/api/v1/feed?page=${i}`, 200, 1500, 'Python-urllib/3.10');
      this.onEventCallback(line, { scenario: 'ddos-burst', step: i + 1, total });
      if (i % 5 === 0) {
        await this.sleep(50);
      }
    }

    return { success: true, simId, scenario: 'ddos-burst', eventCount: total, attackerIp: ip };
  }

  /**
   * Multi-Vector APT Assault Scenario
   */
  async runMultiVector(simId) {
    // 1. Initial Recon / Fuzzing
    await this.runEndpointFuzzing(`${simId}-recon`);
    await this.sleep(500);

    // 2. Traversal attempt
    await this.runDirectoryTraversal(`${simId}-traversal`);
    await this.sleep(500);

    // 3. SQL Injection exploitation
    await this.runSqlInjection(`${simId}-sqli`);
    await this.sleep(500);

    // 4. SSH Brute Force lateral movement
    await this.runSshBruteForce(`${simId}-ssh`);

    return { success: true, simId, scenario: 'multi-vector', eventCount: '45+' };
  }
}

module.exports = AttackSimulator;
