/**
 * SentinelLog WebSocket Broadcast Service
 * Manages active browser client connections and streams real-time events, alerts, and metrics.
 */

const { WebSocket } = require('ws');

class BroadcastService {
  constructor(wss, options = {}) {
    this.wss = wss;
    this.recentLogsBuffer = [];
    this.maxLogsBuffer = options.maxLogsBuffer || 100;
    this.metricsService = options.metricsService;
    this.detectionEngine = options.detectionEngine;

    this.init();
  }

  init() {
    if (!this.wss) return;

    this.wss.on('connection', (ws, req) => {
      // Send initial snapshot state to the newly connected client
      const initialPayload = {
        type: 'INIT_STATE',
        timestamp: new Date().toISOString(),
        recentLogs: this.recentLogsBuffer,
        alerts: this.detectionEngine ? this.detectionEngine.getAlerts({ limit: 50 }) : [],
        metrics: this.metricsService ? this.metricsService.getMetrics() : {}
      };

      ws.send(JSON.stringify(initialPayload));

      ws.on('message', (message) => {
        try {
          const parsed = JSON.parse(message);
          if (parsed.action === 'PING') {
            ws.send(JSON.stringify({ type: 'PONG', timestamp: new Date().toISOString() }));
          }
        } catch {
          // Ignore malformed client message
        }
      });
    });

    // Hook detection engine alerts to broadcast immediately
    if (this.detectionEngine) {
      this.detectionEngine.onAlert((alert) => {
        this.broadcast({
          type: 'ALERT_TRIGGERED',
          timestamp: new Date().toISOString(),
          alert,
          metrics: this.metricsService ? this.metricsService.getMetrics() : null
        });
      });
    }

    // Broadcast periodic metric updates every 1000ms
    this.metricInterval = setInterval(() => {
      if (this.metricsService && this.getClientCount() > 0) {
        this.broadcast({
          type: 'METRICS_UPDATE',
          timestamp: new Date().toISOString(),
          metrics: this.metricsService.getMetrics()
        });
      }
    }, 1000);
    if (this.metricInterval.unref) this.metricInterval.unref();
  }

  /**
   * Broadcast a log event to all connected clients.
   * @param {object} log 
   */
  broadcastLog(log) {
    this.recentLogsBuffer.unshift(log);
    if (this.recentLogsBuffer.length > this.maxLogsBuffer) {
      this.recentLogsBuffer.pop();
    }

    this.broadcast({
      type: 'LOG_INGESTED',
      timestamp: new Date().toISOString(),
      log
    });
  }

  /**
   * Broadcast simulation step updates.
   * @param {object} simData 
   */
  broadcastSimulationUpdate(simData) {
    this.broadcast({
      type: 'SIMULATION_UPDATE',
      timestamp: new Date().toISOString(),
      ...simData
    });
  }

  /**
   * Broadcast a generic message to all OPEN WebSocket clients.
   * @param {object} data 
   */
  broadcast(data) {
    if (!this.wss) return;
    const message = JSON.stringify(data);

    this.wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(message);
        } catch (err) {
          console.error('WebSocket send error:', err);
        }
      }
    });
  }

  /**
   * Return number of active connected clients.
   */
  getClientCount() {
    if (!this.wss) return 0;
    return this.wss.clients.size;
  }

  /**
   * Clear in-memory log buffer.
   */
  clearLogs() {
    this.recentLogsBuffer = [];
    this.broadcast({ type: 'LOGS_CLEARED' });
  }

  destroy() {
    if (this.metricInterval) clearInterval(this.metricInterval);
  }
}

module.exports = BroadcastService;
