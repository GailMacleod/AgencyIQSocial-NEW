const axios = require('axios');
const fs = require('fs');
const path = require('path');

class MonitoringSystem {
  constructor() {
    this.baseUrl = 'http://localhost:5000';
    this.sessionCookie = null;
    this.monitoringResults = {
      endpoints: [],
      sessions: [],
      errors: [],
      performance: [],
      recurring: []
    };
    this.logFilePath = path.join(__dirname, 'logs', 'monitoring-report.json');
  }

  async initializeMonitoring() {
    console.log('📊 INITIALIZING COMPREHENSIVE MONITORING SYSTEM');
    console.log('='.repeat(60));
    
    // Ensure logs directory exists
    const logsDir = path.join(__dirname, 'logs');
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
    
    await this.establishTestSession();
    await this.monitorCriticalEndpoints();
    await this.monitorSessionPersistence();
    await this.analyzeRecurringErrors();
    await this.generateMonitoringReport();
    await this.saveMonitoringData();
  }

  async establishTestSession() {
    console.log('\n🔐 Establishing monitoring session...');
    
    try {
      const sessionRes = await axios.post(`${this.baseUrl}/api/establish-session`, {
        email: 'gailm@macleodglba.com.au',
        phone: '+61424835189'
      });
      
      const cookies = sessionRes.headers['set-cookie'];
      this.sessionCookie = cookies ? cookies[0].split(';')[0] : null;
      
      console.log('✅ Monitoring session established');
      
      this.monitoringResults.sessions.push({
        timestamp: new Date().toISOString(),
        action: 'session_establishment',
        status: 'success',
        responseTime: sessionRes.headers['x-response-time'] || 'N/A',
        sessionId: this.sessionCookie ? 'present' : 'missing'
      });
      
    } catch (error) {
      console.log('❌ Failed to establish monitoring session');
      this.monitoringResults.sessions.push({
        timestamp: new Date().toISOString(),
        action: 'session_establishment',
        status: 'failed',
        error: error.message
      });
    }
  }

  async monitorCriticalEndpoints() {
    console.log('\n📡 Monitoring critical endpoints...');
    
    const criticalEndpoints = [
      { path: '/api/user', name: 'User Authentication' },
      { path: '/api/subscription-usage', name: 'Subscription Status' },
      { path: '/api/brand-purpose', name: 'Brand Purpose Data' },
      { path: '/api/platform-connections', name: 'Platform Connections' },
      { path: '/api/analytics', name: 'Analytics Data' },
      { path: '/api/direct-publish', name: 'Direct Publishing', method: 'POST', data: { action: 'test' } }
    ];
    
    for (const endpoint of criticalEndpoints) {
      await this.monitorEndpoint(endpoint);
    }
  }

  async monitorEndpoint(endpoint) {
    const startTime = Date.now();
    
    try {
      const config = {
        method: endpoint.method || 'GET',
        url: `${this.baseUrl}${endpoint.path}`,
        headers: this.sessionCookie ? { 'Cookie': this.sessionCookie } : {},
        timeout: 10000
      };
      
      if (endpoint.data) {
        config.data = endpoint.data;
      }
      
      const response = await axios(config);
      const responseTime = Date.now() - startTime;
      
      console.log(`   ✅ ${endpoint.name}: ${response.status} (${responseTime}ms)`);
      
      this.monitoringResults.endpoints.push({
        timestamp: new Date().toISOString(),
        endpoint: endpoint.path,
        name: endpoint.name,
        status: 'success',
        httpStatus: response.status,
        responseTime: responseTime,
        dataSize: JSON.stringify(response.data).length,
        hasData: response.data && Object.keys(response.data).length > 0
      });
      
      this.monitoringResults.performance.push({
        endpoint: endpoint.path,
        responseTime: responseTime,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      console.log(`   ❌ ${endpoint.name}: ${error.response?.status || 'Error'} (${responseTime}ms)`);
      
      this.monitoringResults.endpoints.push({
        timestamp: new Date().toISOString(),
        endpoint: endpoint.path,
        name: endpoint.name,
        status: 'failed',
        httpStatus: error.response?.status || 'timeout',
        responseTime: responseTime,
        error: error.message,
        errorType: this.categorizeError(error)
      });
      
      this.monitoringResults.errors.push({
        timestamp: new Date().toISOString(),
        endpoint: endpoint.path,
        error: error.message,
        type: this.categorizeError(error),
        httpStatus: error.response?.status
      });
    }
  }

  categorizeError(error) {
    if (error.code === 'ECONNREFUSED') return 'connection_refused';
    if (error.code === 'ENOTFOUND') return 'dns_error';
    if (error.code === 'ETIMEDOUT') return 'timeout';
    if (error.response?.status === 401) return 'authentication_error';
    if (error.response?.status === 403) return 'authorization_error';
    if (error.response?.status === 404) return 'not_found';
    if (error.response?.status === 500) return 'server_error';
    return 'unknown_error';
  }

  async monitorSessionPersistence() {
    console.log('\n🔒 Monitoring session persistence...');
    
    if (!this.sessionCookie) {
      console.log('❌ No session cookie available for persistence testing');
      return;
    }
    
    // Test session persistence over time
    const persistenceTests = [
      { delay: 0, name: 'Immediate' },
      { delay: 1000, name: '1 second' },
      { delay: 5000, name: '5 seconds' },
      { delay: 10000, name: '10 seconds' }
    ];
    
    for (const test of persistenceTests) {
      await new Promise(resolve => setTimeout(resolve, test.delay));
      
      try {
        const response = await axios.get(`${this.baseUrl}/api/user`, {
          headers: { 'Cookie': this.sessionCookie },
          timeout: 5000
        });
        
        console.log(`   ✅ Session valid after ${test.name}: ${response.status}`);
        
        this.monitoringResults.sessions.push({
          timestamp: new Date().toISOString(),
          action: 'session_persistence',
          testName: test.name,
          status: 'success',
          userId: response.data.id || 'unknown'
        });
        
      } catch (error) {
        console.log(`   ❌ Session failed after ${test.name}: ${error.response?.status || 'Error'}`);
        
        this.monitoringResults.sessions.push({
          timestamp: new Date().toISOString(),
          action: 'session_persistence',
          testName: test.name,
          status: 'failed',
          error: error.message
        });
      }
    }
  }

  async analyzeRecurringErrors() {
    console.log('\n🔍 Analyzing recurring error patterns...');
    
    // Load existing monitoring data if available
    let historicalData = [];
    if (fs.existsSync(this.logFilePath)) {
      try {
        const data = fs.readFileSync(this.logFilePath, 'utf8');
        historicalData = JSON.parse(data);
      } catch (error) {
        console.log('   ⚠️  Could not load historical data');
      }
    }
    
    // Analyze current and historical errors
    const allErrors = [...this.monitoringResults.errors];
    if (historicalData.length > 0) {
      const recentHistorical = historicalData.slice(-50); // Last 50 entries
      recentHistorical.forEach(entry => {
        if (entry.errors) {
          allErrors.push(...entry.errors);
        }
      });
    }
    
    // Find recurring patterns
    const errorPatterns = {};
    allErrors.forEach(error => {
      const pattern = `${error.endpoint}:${error.type}`;
      if (!errorPatterns[pattern]) {
        errorPatterns[pattern] = {
          count: 0,
          firstSeen: error.timestamp,
          lastSeen: error.timestamp,
          endpoints: new Set(),
          types: new Set()
        };
      }
      errorPatterns[pattern].count++;
      errorPatterns[pattern].lastSeen = error.timestamp;
      errorPatterns[pattern].endpoints.add(error.endpoint);
      errorPatterns[pattern].types.add(error.type);
    });
    
    // Identify recurring issues
    const recurringIssues = Object.entries(errorPatterns)
      .filter(([pattern, data]) => data.count > 2)
      .map(([pattern, data]) => ({
        pattern,
        count: data.count,
        endpoints: Array.from(data.endpoints),
        types: Array.from(data.types),
        firstSeen: data.firstSeen,
        lastSeen: data.lastSeen
      }));
    
    this.monitoringResults.recurring = recurringIssues;
    
    console.log(`   📊 Found ${recurringIssues.length} recurring error patterns`);
    recurringIssues.forEach(issue => {
      console.log(`   🔄 ${issue.pattern}: ${issue.count} occurrences`);
    });
  }

  async generateMonitoringReport() {
    console.log('\n📋 COMPREHENSIVE MONITORING REPORT');
    console.log('='.repeat(60));
    
    const successfulEndpoints = this.monitoringResults.endpoints.filter(e => e.status === 'success');
    const failedEndpoints = this.monitoringResults.endpoints.filter(e => e.status === 'failed');
    const averageResponseTime = this.monitoringResults.performance.reduce((sum, p) => sum + p.responseTime, 0) / 
                               this.monitoringResults.performance.length;
    
    console.log(`\n📊 MONITORING SUMMARY:`);
    console.log(`   🌐 Endpoints monitored: ${this.monitoringResults.endpoints.length}`);
    console.log(`   ✅ Successful requests: ${successfulEndpoints.length}`);
    console.log(`   ❌ Failed requests: ${failedEndpoints.length}`);
    console.log(`   ⚡ Average response time: ${Math.round(averageResponseTime)}ms`);
    console.log(`   🔒 Session tests: ${this.monitoringResults.sessions.length}`);
    console.log(`   🔄 Recurring issues: ${this.monitoringResults.recurring.length}`);
    
    console.log(`\n⚡ PERFORMANCE METRICS:`);
    this.monitoringResults.performance.forEach(perf => {
      const status = perf.responseTime < 100 ? '🟢' : 
                    perf.responseTime < 500 ? '🟡' : '🔴';
      console.log(`   ${status} ${perf.endpoint}: ${perf.responseTime}ms`);
    });
    
    if (failedEndpoints.length > 0) {
      console.log(`\n❌ FAILED ENDPOINTS:`);
      failedEndpoints.forEach(endpoint => {
        console.log(`   🔴 ${endpoint.name}: ${endpoint.error || 'Unknown error'}`);
      });
    }
    
    if (this.monitoringResults.recurring.length > 0) {
      console.log(`\n🔄 RECURRING ISSUES:`);
      this.monitoringResults.recurring.forEach(issue => {
        console.log(`   🔄 ${issue.pattern}: ${issue.count} occurrences`);
        console.log(`      First seen: ${issue.firstSeen}`);
        console.log(`      Last seen: ${issue.lastSeen}`);
      });
    }
    
    // Overall health assessment
    const healthScore = (successfulEndpoints.length / this.monitoringResults.endpoints.length) * 100;
    const healthStatus = healthScore >= 95 ? 'EXCELLENT' : 
                        healthScore >= 85 ? 'GOOD' : 
                        healthScore >= 70 ? 'NEEDS ATTENTION' : 'CRITICAL';
    
    console.log(`\n🎯 SYSTEM HEALTH: ${healthStatus} (${Math.round(healthScore)}%)`);
    
    // Recommendations
    console.log(`\n💡 RECOMMENDATIONS:`);
    
    if (averageResponseTime > 500) {
      console.log(`   📈 Performance: Average response time is high (${Math.round(averageResponseTime)}ms)`);
    }
    
    if (this.monitoringResults.recurring.length > 0) {
      console.log(`   🔄 Recurring Issues: ${this.monitoringResults.recurring.length} patterns need investigation`);
    }
    
    if (failedEndpoints.length > 0) {
      console.log(`   ❌ Failed Endpoints: ${failedEndpoints.length} endpoints need immediate attention`);
    }
    
    if (healthScore < 85) {
      console.log(`   🚨 Critical: System health below 85% - immediate action required`);
    }
  }

  async saveMonitoringData() {
    console.log('\n💾 Saving monitoring data...');
    
    const monitoringEntry = {
      timestamp: new Date().toISOString(),
      summary: {
        endpointsMonitored: this.monitoringResults.endpoints.length,
        successful: this.monitoringResults.endpoints.filter(e => e.status === 'success').length,
        failed: this.monitoringResults.endpoints.filter(e => e.status === 'failed').length,
        averageResponseTime: this.monitoringResults.performance.reduce((sum, p) => sum + p.responseTime, 0) / 
                           this.monitoringResults.performance.length
      },
      ...this.monitoringResults
    };
    
    // Load existing data
    let existingData = [];
    if (fs.existsSync(this.logFilePath)) {
      try {
        const data = fs.readFileSync(this.logFilePath, 'utf8');
        existingData = JSON.parse(data);
      } catch (error) {
        console.log('   ⚠️  Could not load existing data, creating new file');
      }
    }
    
    // Add new entry and keep only last 100 entries
    existingData.push(monitoringEntry);
    existingData = existingData.slice(-100);
    
    // Save data
    try {
      fs.writeFileSync(this.logFilePath, JSON.stringify(existingData, null, 2));
      console.log(`   ✅ Monitoring data saved to ${this.logFilePath}`);
    } catch (error) {
      console.log(`   ❌ Failed to save monitoring data: ${error.message}`);
    }
  }
}

// Execute the monitoring system
const monitor = new MonitoringSystem();
monitor.initializeMonitoring();