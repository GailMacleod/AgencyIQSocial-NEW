/**
 * Enhanced Logging System
 * Console and file logging with proper production configuration
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class Logger {
  constructor() {
    this.logsDir = path.join(__dirname, '../../logs');
    this.ensureLogsDirectory();
    
    this.logLevels = {
      ERROR: 0,
      WARN: 1,
      INFO: 2,
      DEBUG: 3
    };
    
    this.currentLevel = process.env.NODE_ENV === 'production' 
      ? this.logLevels.INFO 
      : this.logLevels.DEBUG;
  }

  ensureLogsDirectory() {
    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true });
    }
  }

  formatMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      pid: process.pid,
      ...meta
    };

    return JSON.stringify(logEntry);
  }

  writeToFile(level, formattedMessage) {
    try {
      const date = new Date().toISOString().split('T')[0];
      const filename = `theagencyiq-${date}.log`;
      const filepath = path.join(this.logsDir, filename);
      
      fs.appendFileSync(filepath, formattedMessage + '\n');
      
      // Keep only last 7 days of logs
      this.cleanupOldLogs();
    } catch (error) {
      console.error('Failed to write to log file:', error);
    }
  }

  cleanupOldLogs() {
    try {
      const files = fs.readdirSync(this.logsDir);
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
      
      files.forEach(file => {
        const filepath = path.join(this.logsDir, file);
        const stats = fs.statSync(filepath);
        
        if (stats.mtime < sevenDaysAgo) {
          fs.unlinkSync(filepath);
        }
      });
    } catch (error) {
      // Ignore cleanup errors
    }
  }

  log(level, message, meta = {}) {
    if (this.logLevels[level] > this.currentLevel) {
      return;
    }

    const formattedMessage = this.formatMessage(level, message, meta);
    
    // Always log to console
    const consoleMethod = level === 'ERROR' ? 'error' : 
                         level === 'WARN' ? 'warn' : 'log';
    console[consoleMethod](`[${level}] ${message}`, meta);
    
    // Log to file in production or if explicitly enabled
    if (process.env.NODE_ENV === 'production' || process.env.LOG_TO_FILE === 'true') {
      this.writeToFile(level, formattedMessage);
    }
  }

  error(message, meta = {}) {
    this.log('ERROR', message, meta);
  }

  warn(message, meta = {}) {
    this.log('WARN', message, meta);
  }

  info(message, meta = {}) {
    this.log('INFO', message, meta);
  }

  debug(message, meta = {}) {
    this.log('DEBUG', message, meta);
  }

  // OAuth specific logging
  oauth(action, platform, userId, meta = {}) {
    this.info(`OAuth ${action}`, {
      platform,
      userId,
      action,
      category: 'oauth',
      ...meta
    });
  }

  // Quota specific logging
  quota(action, platform, userId, usage, meta = {}) {
    this.info(`Quota ${action}`, {
      platform,
      userId,
      usage,
      category: 'quota',
      ...meta
    });
  }

  // Security specific logging
  security(event, details, meta = {}) {
    this.warn(`Security Event: ${event}`, {
      event,
      details,
      category: 'security',
      ...meta
    });
  }
}

// Create singleton instance
export const logger = new Logger();

// Express middleware for request logging
export function requestLogger(req, res, next) {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logLevel = res.statusCode >= 400 ? 'WARN' : 'INFO';
    
    logger.log(logLevel, `${req.method} ${req.path}`, {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      userId: req.userId,
      category: 'request'
    });
  });
  
  next();
}