const fs = require('fs');
const path = require('path');

class MiddlewareAuditor {
  constructor() {
    this.auditResults = [];
    this.subscriptionFields = [
      'subscriptionActive',
      'subscriptionPlan', 
      'subscriptionId',
      'stripeCustomerId',
      'stripeSubscriptionId',
      'remainingPosts',
      'totalPosts',
      'usedPosts'
    ];
  }

  async auditMiddlewareFiles() {
    console.log('🔍 MIDDLEWARE AUDIT: Checking Subscription Field Consistency');
    console.log('='.repeat(65));
    
    const middlewareDir = path.join(__dirname, 'server', 'middleware');
    const serverFiles = [
      'server/routes.ts',
      'server/storage.ts',
      'server/subscription-service.ts',
      'server/middleware/subscriptionAuth.ts'
    ];
    
    // Check if middleware directory exists
    if (fs.existsSync(middlewareDir)) {
      console.log('✅ Middleware directory found');
      const middlewareFiles = fs.readdirSync(middlewareDir)
        .filter(f => f.endsWith('.ts') || f.endsWith('.js'))
        .map(f => path.join(middlewareDir, f));
      
      serverFiles.push(...middlewareFiles);
    } else {
      console.log('⚠️  No dedicated middleware directory found');
    }
    
    // Audit each file
    for (const filePath of serverFiles) {
      if (fs.existsSync(filePath)) {
        await this.auditFile(filePath);
      }
    }
    
    this.generateAuditReport();
  }

  async auditFile(filePath) {
    console.log(`\n📄 Auditing: ${filePath}`);
    
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');
      
      const fileAudit = {
        file: filePath,
        subscriptionChecks: [],
        middlewarePatterns: [],
        potentialIssues: [],
        recommendations: []
      };
      
      // Check for subscription field usage
      lines.forEach((line, index) => {
        const lineNumber = index + 1;
        
        // Check for subscription field references
        this.subscriptionFields.forEach(field => {
          if (line.includes(field)) {
            fileAudit.subscriptionChecks.push({
              line: lineNumber,
              field: field,
              context: line.trim(),
              type: this.categorizeUsage(line, field)
            });
          }
        });
        
        // Check for middleware patterns
        if (line.includes('requireActiveSubscription') || 
            line.includes('requirePaidSubscription') ||
            line.includes('subscriptionAuth') ||
            line.includes('checkSubscription')) {
          fileAudit.middlewarePatterns.push({
            line: lineNumber,
            pattern: line.trim(),
            type: 'middleware_usage'
          });
        }
        
        // Check for potential issues
        if (line.includes('|| 1') || line.includes('|| 2') || line.includes('|| "default"')) {
          fileAudit.potentialIssues.push({
            line: lineNumber,
            issue: 'Fallback user ID pattern detected',
            context: line.trim(),
            severity: 'HIGH'
          });
        }
        
        if (line.includes('subscriptionActive') && !line.includes('===') && !line.includes('==')) {
          fileAudit.potentialIssues.push({
            line: lineNumber,
            issue: 'Subscription active check without strict equality',
            context: line.trim(),
            severity: 'MEDIUM'
          });
        }
      });
      
      // Generate recommendations
      this.generateFileRecommendations(fileAudit);
      
      this.auditResults.push(fileAudit);
      
      console.log(`   📊 Found ${fileAudit.subscriptionChecks.length} subscription field references`);
      console.log(`   🔧 Found ${fileAudit.middlewarePatterns.length} middleware patterns`);
      console.log(`   ⚠️  Found ${fileAudit.potentialIssues.length} potential issues`);
      
    } catch (error) {
      console.log(`   ❌ Error reading file: ${error.message}`);
    }
  }

  categorizeUsage(line, field) {
    if (line.includes('req.session') || line.includes('session.')) {
      return 'session_access';
    } else if (line.includes('res.json') || line.includes('response')) {
      return 'response_field';
    } else if (line.includes('if') || line.includes('&&') || line.includes('||')) {
      return 'conditional_check';
    } else if (line.includes('=') && !line.includes('==')) {
      return 'assignment';
    } else {
      return 'unknown';
    }
  }

  generateFileRecommendations(fileAudit) {
    // Check for inconsistent subscription checks
    const subscriptionActiveChecks = fileAudit.subscriptionChecks.filter(
      check => check.field === 'subscriptionActive'
    );
    
    if (subscriptionActiveChecks.length > 0) {
      const hasStrictCheck = subscriptionActiveChecks.some(
        check => check.context.includes('=== true') || check.context.includes('=== false')
      );
      
      if (!hasStrictCheck) {
        fileAudit.recommendations.push({
          type: 'consistency',
          message: 'Use strict equality (=== true) for subscriptionActive checks',
          priority: 'HIGH'
        });
      }
    }
    
    // Check for middleware consistency
    if (fileAudit.middlewarePatterns.length === 0 && fileAudit.subscriptionChecks.length > 0) {
      fileAudit.recommendations.push({
        type: 'security',
        message: 'Consider using middleware for subscription validation instead of inline checks',
        priority: 'MEDIUM'
      });
    }
  }

  generateAuditReport() {
    console.log('\n📋 MIDDLEWARE AUDIT COMPREHENSIVE REPORT');
    console.log('='.repeat(65));
    
    const totalIssues = this.auditResults.reduce((sum, audit) => sum + audit.potentialIssues.length, 0);
    const totalRecommendations = this.auditResults.reduce((sum, audit) => sum + audit.recommendations.length, 0);
    const filesWithIssues = this.auditResults.filter(audit => audit.potentialIssues.length > 0).length;
    
    console.log(`\n📊 AUDIT SUMMARY:`);
    console.log(`   📁 Files audited: ${this.auditResults.length}`);
    console.log(`   🔍 Subscription field references: ${this.getTotalSubscriptionReferences()}`);
    console.log(`   🔧 Middleware patterns: ${this.getTotalMiddlewarePatterns()}`);
    console.log(`   ⚠️  Potential issues: ${totalIssues}`);
    console.log(`   💡 Recommendations: ${totalRecommendations}`);
    console.log(`   📄 Files with issues: ${filesWithIssues}`);
    
    console.log(`\n🔍 DETAILED AUDIT RESULTS:`);
    
    this.auditResults.forEach(audit => {
      if (audit.potentialIssues.length > 0 || audit.recommendations.length > 0) {
        console.log(`\n📄 ${audit.file}:`);
        
        // Show potential issues
        audit.potentialIssues.forEach(issue => {
          const severityIcon = issue.severity === 'HIGH' ? '🔴' : 
                              issue.severity === 'MEDIUM' ? '🟡' : '🟢';
          console.log(`   ${severityIcon} Line ${issue.line}: ${issue.issue}`);
          console.log(`      Context: ${issue.context}`);
        });
        
        // Show recommendations
        audit.recommendations.forEach(rec => {
          const priorityIcon = rec.priority === 'HIGH' ? '🔴' : 
                              rec.priority === 'MEDIUM' ? '🟡' : '🟢';
          console.log(`   ${priorityIcon} ${rec.type.toUpperCase()}: ${rec.message}`);
        });
      }
    });
    
    console.log(`\n🎯 CRITICAL RECOMMENDATIONS:`);
    
    const highPriorityIssues = this.auditResults.flatMap(audit => 
      audit.potentialIssues.filter(issue => issue.severity === 'HIGH')
    );
    
    if (highPriorityIssues.length > 0) {
      console.log(`   🔴 ${highPriorityIssues.length} HIGH PRIORITY issues require immediate attention`);
      highPriorityIssues.forEach(issue => {
        console.log(`      - ${issue.issue} (multiple files)`);
      });
    }
    
    const highPriorityRecs = this.auditResults.flatMap(audit => 
      audit.recommendations.filter(rec => rec.priority === 'HIGH')
    );
    
    if (highPriorityRecs.length > 0) {
      console.log(`   🔴 ${highPriorityRecs.length} HIGH PRIORITY recommendations:`);
      highPriorityRecs.forEach(rec => {
        console.log(`      - ${rec.message}`);
      });
    }
    
    // Overall assessment
    const overallStatus = totalIssues === 0 ? 'EXCELLENT' : 
                         totalIssues < 5 ? 'GOOD' : 
                         totalIssues < 10 ? 'NEEDS ATTENTION' : 'CRITICAL';
    
    console.log(`\n🚀 MIDDLEWARE CONSISTENCY STATUS: ${overallStatus}`);
    
    if (overallStatus === 'CRITICAL') {
      console.log(`   ⚠️  Immediate action required on ${totalIssues} issues`);
    } else if (overallStatus === 'NEEDS ATTENTION') {
      console.log(`   📋 Review and address ${totalIssues} issues when possible`);
    } else {
      console.log(`   ✅ Middleware consistency is well-maintained`);
    }
  }

  getTotalSubscriptionReferences() {
    return this.auditResults.reduce((sum, audit) => sum + audit.subscriptionChecks.length, 0);
  }

  getTotalMiddlewarePatterns() {
    return this.auditResults.reduce((sum, audit) => sum + audit.middlewarePatterns.length, 0);
  }
}

// Execute the middleware audit
const auditor = new MiddlewareAuditor();
auditor.auditMiddlewareFiles();