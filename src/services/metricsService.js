/**
 * SentinelLog Metrics Aggregator Service
 * Real-time calculation of SOC KPIs, threat distributions, and throughput rates.
 */

class MetricsService {
  constructor(detectionEngine) {
    this.engine = detectionEngine;
    this.totalEvents = 0;
    this.totalParsedSuccess = 0;
    this.totalParsedFailed = 0;
    this.ipActivity = new Map(); // ip -> { requests: number, alerts: number, lastSeen: string }
    this.eventsPerSecondHistory = []; // array of { time: string, count: number }
    this.currentSecondCount = 0;
    this.lastSecondTimestamp = Math.floor(Date.now() / 1000);

    // Track throughput every second
    this.velocityInterval = setInterval(() => this.tickVelocity(), 1000);
    if (this.velocityInterval.unref) this.velocityInterval.unref();

    // Attach to detection engine alerts
    if (this.engine) {
      this.engine.onAlert((alert) => {
        if (alert.attackerIp) {
          const ipData = this.ipActivity.get(alert.attackerIp) || { requests: 0, alerts: 0, lastSeen: new Date().toISOString() };
          ipData.alerts += 1;
          ipData.lastSeen = new Date().toISOString();
          this.ipActivity.set(alert.attackerIp, ipData);
        }
      });
    }
  }

  /**
   * Called on each incoming raw/parsed log event.
   * @param {object} log 
   */
  recordEvent(log) {
    this.totalEvents += 1;
    this.currentSecondCount += 1;

    if (log.parsed) {
      this.totalParsedSuccess += 1;
    } else {
      this.totalParsedFailed += 1;
    }

    if (log.ip) {
      const ipData = this.ipActivity.get(log.ip) || { requests: 0, alerts: 0, lastSeen: new Date().toISOString() };
      ipData.requests += 1;
      ipData.lastSeen = log.timestamp || new Date().toISOString();
      this.ipActivity.set(log.ip, ipData);
    }
  }

  /**
   * Periodic tick to compute events per second for the line chart.
   */
  tickVelocity() {
    const currentSec = Math.floor(Date.now() / 1000);
    const timeLabel = new Date().toTimeString().split(' ')[0];

    this.eventsPerSecondHistory.push({
      time: timeLabel,
      timestamp: currentSec * 1000,
      eps: this.currentSecondCount
    });

    this.currentSecondCount = 0;
    this.lastSecondTimestamp = currentSec;

    // Keep last 30 data points (30 seconds)
    if (this.eventsPerSecondHistory.length > 30) {
      this.eventsPerSecondHistory.shift();
    }
  }

  /**
   * Generate full SOC metrics payload.
   * @returns {object}
   */
  getMetrics() {
    const alerts = this.engine ? this.engine.alerts : [];
    
    // Severity breakdown
    const severityCounts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Info: 0
    };

    // Rule breakdown
    const ruleCounts = {
      'RULE-001': 0,
      'RULE-002': 0,
      'RULE-003': 0,
      'RULE-004': 0
    };

    for (const a of alerts) {
      if (severityCounts[a.severity] !== undefined) {
        severityCounts[a.severity] += 1;
      } else {
        severityCounts.Info += 1;
      }

      if (ruleCounts[a.ruleId] !== undefined) {
        ruleCounts[a.ruleId] += 1;
      }
    }

    // Top 5 Attacker IPs
    const sortedIps = Array.from(this.ipActivity.entries())
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => (b.alerts * 10 + b.requests) - (a.alerts * 10 + a.requests))
      .slice(0, 5);

    // Current EPS
    const currentEps = this.eventsPerSecondHistory.length > 0
      ? this.eventsPerSecondHistory[this.eventsPerSecondHistory.length - 1].eps
      : 0;

    return {
      totalEvents: this.totalEvents,
      totalParsedSuccess: this.totalParsedSuccess,
      totalParsedFailed: this.totalParsedFailed,
      totalAlerts: alerts.length,
      activeHighAlerts: severityCounts.High + severityCounts.Critical,
      activeMediumAlerts: severityCounts.Medium,
      activeLowAlerts: severityCounts.Low + severityCounts.Info,
      severityBreakdown: severityCounts,
      ruleBreakdown: ruleCounts,
      topAttackers: sortedIps,
      currentEps,
      velocityHistory: this.eventsPerSecondHistory,
      systemHealth: 'OPERATIONAL',
      uptimeSeconds: Math.floor(process.uptime())
    };
  }

  /**
   * Reset metrics.
   */
  reset() {
    this.totalEvents = 0;
    this.totalParsedSuccess = 0;
    this.totalParsedFailed = 0;
    this.ipActivity.clear();
    this.eventsPerSecondHistory = [];
    this.currentSecondCount = 0;
  }

  /**
   * Cleanup
   */
  destroy() {
    if (this.velocityInterval) clearInterval(this.velocityInterval);
  }
}

module.exports = MetricsService;
