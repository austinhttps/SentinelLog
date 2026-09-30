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
   * GET /api/samples/:filename
   * Retrieve raw text of sample log files from samples/ directory.
   */
  router.get('/samples/:filename', (req, res) => {
    try {
      const fs = require('fs');
      const path = require('path');
      let fname = req.params.filename || '';
      if (fname === 'mixed.log' || fname === 'mixed') fname = 'mixed_attacks.log';
      if (!fname.endsWith('.log')) fname += '.log';

      const safePath = path.join(__dirname, '..', '..', 'samples', path.basename(fname));
      if (!fs.existsSync(safePath)) {
        return res.status(404).json({ error: `Sample file '${fname}' not found.` });
      }

      const content = fs.readFileSync(safePath, 'utf8');
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      return res.send(content);
    } catch (err) {
      return res.status(500).json({ error: 'Failed to read sample file', details: err.message });
    }
  });

  /**
   * POST /api/samples/load/:filename
   * Load and dynamically stream a sample log fixture through the SIEM pipeline.
   */
  router.post('/samples/load/:filename', async (req, res) => {
    try {
      const fs = require('fs');
      const path = require('path');
      let fname = req.params.filename || '';
      if (fname === 'mixed.log' || fname === 'mixed') fname = 'mixed_attacks.log';
      if (!fname.endsWith('.log')) fname += '.log';

      const safePath = path.join(__dirname, '..', '..', 'samples', path.basename(fname));
      if (!fs.existsSync(safePath)) {
        return res.status(404).json({ error: `Sample file '${fname}' not found.` });
      }

      const rawContent = fs.readFileSync(safePath, 'utf8');
      const lines = rawContent.split(/\r?\n/).filter(l => l.trim() && !l.trim().startsWith('#'));

      const now = new Date();
      let parsedCount = 0;
      let totalAlerts = 0;

      // Ingest each line with real-time timestamp adaptation
      for (let i = 0; i < lines.length; i++) {
        let line = lines[i];
        
        // Dynamically update timestamp in log line to current relative time
        const lineTime = new Date(now.getTime() - (lines.length - i) * 800);
        const day = String(lineTime.getDate()).padStart(2, '0');
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const month = months[lineTime.getMonth()];
        const year = lineTime.getFullYear();
        const timeStr = lineTime.toTimeString().split(' ')[0];

        // Replace access log date: e.g. [30/Sep/2026:14:00:10 +0000] -> [DD/Mon/YYYY:HH:mm:ss +0000]
        line = line.replace(/\[\d{1,2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4}\]/, `[${day}/${month}/${year}:${timeStr} +0000]`);

        // Replace syslog date: e.g. Sep 30 14:00:01 -> Mon DD HH:mm:ss
        line = line.replace(/^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/, `${month} ${String(lineTime.getDate()).padStart(2, ' ')} ${timeStr}`);

        const result = ingestLine(line);
        if (result) {
          if (result.parsed && result.parsed.parsed) parsedCount++;
          if (result.alerts && result.alerts.length > 0) totalAlerts += result.alerts.length;
        }
      }

      return res.json({
        success: true,
        filename: fname,
        totalLines: lines.length,
        parsedCount,
        alertsTriggered: totalAlerts,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('Error loading sample fixture:', err);
      return res.status(500).json({ error: 'Failed to load sample fixture', details: err.message });
    }
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
