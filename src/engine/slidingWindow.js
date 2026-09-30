/**
 * SentinelLog In-Memory Sliding Window Tracker
 * Provides sliding-window state aggregation per IP with automatic TTL pruning.
 */

class SlidingWindowTracker {
  constructor(options = {}) {
    // Default TTL for memory cleanup: 10 minutes
    this.maxTtlMs = options.maxTtlMs || 10 * 60 * 1000;
    // Map of IP -> Map of eventType -> Array<{ timestamp: number, data: any }>
    this.windows = new Map();
    // Periodically prune stale IPs every 60s
    if (options.autoPrune !== false) {
      this.pruneInterval = setInterval(() => this.pruneExpired(), 60000);
      if (this.pruneInterval.unref) this.pruneInterval.unref();
    }
  }

  /**
   * Record an event in the sliding window.
   * @param {string} ip 
   * @param {string} eventType 
   * @param {number|string|Date} timestamp 
   * @param {any} data 
   */
  record(ip, eventType, timestamp = Date.now(), data = {}) {
    if (!ip) return;
    const ts = typeof timestamp === 'number' ? timestamp : new Date(timestamp).getTime();
    if (isNaN(ts)) return;

    if (!this.windows.has(ip)) {
      this.windows.set(ip, new Map());
    }

    const ipMap = this.windows.get(ip);
    if (!ipMap.has(eventType)) {
      ipMap.set(eventType, []);
    }

    const eventList = ipMap.get(eventType);
    eventList.push({ timestamp: ts, data });

    // Keep events sorted or prune anything older than maxTtlMs from current ts
    const cutoff = ts - this.maxTtlMs;
    while (eventList.length > 0 && eventList[0].timestamp < cutoff) {
      eventList.shift();
    }
  }

  /**
   * Get all events for an IP & type within a given time window (in ms) relative to referenceTime.
   * @param {string} ip 
   * @param {string} eventType 
   * @param {number} windowMs 
   * @param {number|Date} referenceTime 
   * @returns {Array<object>}
   */
  getEvents(ip, eventType, windowMs, referenceTime = Date.now()) {
    if (!ip || !this.windows.has(ip)) return [];
    const ipMap = this.windows.get(ip);
    if (!ipMap.has(eventType)) return [];

    const refTs = typeof referenceTime === 'number' ? referenceTime : new Date(referenceTime).getTime();
    const cutoff = refTs - windowMs;
    const list = ipMap.get(eventType);

    return list.filter(item => item.timestamp >= cutoff && item.timestamp <= refTs);
  }

  /**
   * Count occurrences for an IP & type within the specified window duration.
   * @param {string} ip 
   * @param {string} eventType 
   * @param {number} windowMs 
   * @param {number|Date} referenceTime 
   * @returns {number}
   */
  count(ip, eventType, windowMs, referenceTime = Date.now()) {
    return this.getEvents(ip, eventType, windowMs, referenceTime).length;
  }

  /**
   * Prune expired records across all IPs.
   */
  pruneExpired(now = Date.now()) {
    const cutoff = now - this.maxTtlMs;
    for (const [ip, ipMap] of this.windows.entries()) {
      for (const [eventType, list] of ipMap.entries()) {
        const filtered = list.filter(item => item.timestamp >= cutoff);
        if (filtered.length === 0) {
          ipMap.delete(eventType);
        } else {
          ipMap.set(eventType, filtered);
        }
      }
      if (ipMap.size === 0) {
        this.windows.delete(ip);
      }
    }
  }

  /**
   * Clear all tracked windows.
   */
  reset() {
    this.windows.clear();
  }

  /**
   * Destroy timer when shutting down.
   */
  destroy() {
    if (this.pruneInterval) {
      clearInterval(this.pruneInterval);
    }
    this.windows.clear();
  }
}

module.exports = SlidingWindowTracker;
