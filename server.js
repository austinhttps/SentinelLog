/**
 * SentinelLog - Real-Time SIEM & Log Ingestion Engine
 * Main Server Entrypoint (Express + Native WebSockets)
 */

const http = require('http');
const path = require('path');
const express = require('express');
const cors = require('cors');
const { WebSocketServer } = require('ws');

const SlidingWindowTracker = require('./src/engine/slidingWindow');
const DetectionEngine = require('./src/engine/detectionEngine');
const MetricsService = require('./src/services/metricsService');
const BroadcastService = require('./src/services/broadcastService');
const AttackSimulator = require('./src/simulation/attackSimulator');
const createApiRoutes = require('./src/routes/apiRoutes');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// Initialize core components
const slidingTracker = new SlidingWindowTracker();
const detectionEngine = new DetectionEngine({ tracker: slidingTracker });
const metricsService = new MetricsService(detectionEngine);
const attackSimulator = new AttackSimulator();

// Set up WebSocket server
const wss = new WebSocketServer({ server, path: '/ws' });
const broadcastService = new BroadcastService(wss, {
  metricsService,
  detectionEngine
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files for SOC Dashboard UI
app.use(express.static(path.join(__dirname, 'public')));

// Mount API routes
app.use('/api', createApiRoutes({
  detectionEngine,
  metricsService,
  broadcastService,
  attackSimulator
}));

// Fallback route for SPA / dashboard
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start listening if run directly
if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`🛡️  SentinelLog SIEM Dashboard running on http://localhost:${PORT}`);
    console.log(`📡 WebSocket endpoint active at ws://localhost:${PORT}/ws`);
    console.log(`⚙️  Ready for real-time log ingestion and threat detection`);
    console.log(`=======================================================`);
  });
}

module.exports = {
  app,
  server,
  detectionEngine,
  metricsService,
  broadcastService,
  attackSimulator
};
