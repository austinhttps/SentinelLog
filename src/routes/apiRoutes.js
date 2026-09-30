/**
 * SentinelLog REST API Routes
 * Ingestion, Simulation Triggers, Alert Queries, and System Telemetry.
 */

const express = require('express');
const multer = require('multer');
const { parseLogLine, parseBatchLogs } = require('../parser/logParser');

// Memory storage for multer file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

function createApiRoutes({ detectionEngine, metricsService, broadcastService, attackSimulator }) {
  const router = express.Router();

  /**
   * Pipeline worker to parse, inspect, update metrics, and broadcast a single raw line.
   */
  function ingestLine(rawLine) {
    if (!rawLine || !rawLine.trim()) return null;
    const parsed = parseLogLine(rawLine);
    
    // Update metrics
    if (metricsService) {
      metricsService.recordEvent(parsed);
    }

    // SIEM Detection correlation
    let triggeredAlerts = [];
    if (detectionEngine) {
      triggeredAlerts = detectionEngine.processEvent(parsed);
    }

    // Broadcast log over WebSocket
    if (broadcastService) {
      broadcastService.broadcastLog(parsed);
    }

    return { parsed, alerts: triggeredAlerts };
  }

  /**
   * POST /api/logs/ingest
   * Ingest raw log string (JSON) or multipart/form-data log file.
   */
  router.post('/logs/ingest', upload.single('file'), (req, res) => {
    try {
      let rawData = '';

      if (req.file) {
        rawData = req.file.buffer.toString('utf8');
      } else if (req.body && req.body.logs) {
        rawData = req.body.logs;
      } else if (req.body && req.body.log) {
        rawData = req.body.log;
      } else if (typeof req.body === 'string') {
        rawData = req.body;
      }

      if (!rawData || !rawData.trim()) {
        return res.status(400).json({
          error: 'No log content provided. Send "logs" in JSON body or upload a file field "file".'
        });
      }

      const lines = rawData.split(/\r?\n/).filter(l => l.trim().length > 0);
      let parsedCount = 0;
      let totalAlerts = 0;
      const results = [];

      for (const line of lines) {
        const result = ingestLine(line);
        if (result) {
          if (result.parsed && result.parsed.parsed) parsedCount++;
          if (result.alerts && result.alerts.length > 0) totalAlerts += result.alerts.length;
          results.push(result);
        }
      }

      return res.json({
        success: true,
        totalLines: lines.length,
        parsedCount,
        unparsedCount: lines.length - parsedCount,
        alertsTriggered: totalAlerts,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('Ingest error:', err);
      return res.status(500).json({ error: 'Internal server error processing log batch', details: err.message });
    }
  });

  /**
   * POST /api/simulate
   * Trigger an automated attack scenario simulation.
   */
  router.post('/simulate', async (req, res) => {
    try {
      const { scenario = 'ssh-brute-force' } = req.body || {};
      
      if (!attackSimulator) {
        return res.status(500).json({ error: 'Attack simulator not initialized.' });
      }

      // Hook simulator events into the live pipeline
      attackSimulator.setEventCallback((rawLine, meta) => {
        ingestLine(rawLine);
        if (broadcastService) {
          broadcastService.broadcastSimulationUpdate(meta);
        }
      });

      // Start the simulation asynchronously or wait
      const simPromise = attackSimulator.runScenario(scenario);

      // Return immediately with simulation started acknowledge
      return res.json({
        success: true,
        message: `Simulation scenario '${scenario}' initiated.`,
        scenario,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('Simulation error:', err);
      return res.status(500).json({ error: 'Failed to execute simulation', details: err.message });
    }
  });

  /**
   * GET /api/scenarios
   * List available pre-scripted attack scenarios.
   */
  router.get('/scenarios', (req, res) => {
    const scenarios = attackSimulator ? attackSimulator.getScenarios() : [];
    return res.json({ success: true, scenarios });
  });

  /**
   * GET /api/alerts
   * Query recent alerts with optional filters.
   */
  router.get('/alerts', (req, res) => {
    const { severity, ruleId, ip, limit } = req.query;
    const alerts = detectionEngine ? detectionEngine.getAlerts({ severity, ruleId, ip, limit }) : [];
    return res.json({
      success: true,
      count: alerts.length,
      alerts
    });
  });

  /**
   * GET /api/metrics
   * Aggregated metrics for dashboard counters, charts, and top attackers.
   */
  router.get('/metrics', (req, res) => {
    const metrics = metricsService ? metricsService.getMetrics() : {};
    return res.json({
      success: true,
      timestamp: new Date().toISOString(),
      metrics
    });
  });

  /**
   * POST /api/reset
   * Clear dashboard state, alerts, and metrics.
   */
  router.post('/reset', (req, res) => {
    if (detectionEngine) detectionEngine.reset();
    if (metricsService) metricsService.reset();
    if (broadcastService) broadcastService.clearLogs();
    
    return res.json({
      success: true,
      message: 'Dashboard and SIEM state reset successfully.'
    });
  });

  return router;
}

module.exports = createApiRoutes;
