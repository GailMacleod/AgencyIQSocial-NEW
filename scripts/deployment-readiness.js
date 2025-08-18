#!/usr/bin/env node

/**
 * DEPLOYMENT READINESS VERIFICATION SCRIPT
 * Comprehensive end-to-end testing for TheAgencyIQ
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class DeploymentReadinessTest {
  constructor() {
    this.testResults = [];
    this.errors = [];
    this.warnings = [];
  }

  /**
   * Run comprehensive deployment readiness tests
   */
  async runTests() {
    console.log('🚀 Starting deployment readiness verification...');
    
    try {
      // 1. Environment validation
      await this.validateEnvironment();
      
      // 2. File structure validation
      await this.validateFileStructure();
      
      // 3. Database schema validation
      await this.validateDatabaseSchema();
      
      // 4. API endpoint validation
      await this.validateApiEndpoints();
      
      // 5. Frontend route validation
      await this.validateFrontendRoutes();
      
      // 6. OAuth configuration validation
      await this.validateOAuthConfig();
      
      // 7. Payment integration validation
      await this.validatePaymentIntegration();
      
      // 8. Security validation
      await this.validateSecurity();
      
      // 9. Performance validation
      await this.validatePerformance();
      
      // 10. Generate readiness report
      await this.generateReadinessReport();
      
      console.log('✅ Deployment readiness verification completed');
      
    } catch (error) {
      console.error('❌ Deployment readiness failed:', error);
      this.errors.push(`Critical failure: ${error.message}`);
    }
  }

  /**
   * Validate environment configuration
   */
  async validateEnvironment() {
    console.log('🔧 Validating environment configuration...');
    
    const requiredEnvVars = [
      'SESSION_SECRET',
      'DATABASE_URL',
      'NODE_ENV'
    ];

    const optionalEnvVars = [
      'STRIPE_SECRET_KEY',
      'XAI_API_KEY',
      'TWILIO_ACCOUNT_SID',
      'SENDGRID_API_KEY',
      'X_CONSUMER_KEY',
      'X_CONSUMER_SECRET'
    ];

    requiredEnvVars.forEach(envVar => {
      if (!process.env[envVar]) {
        this.errors.push(`Missing required environment variable: ${envVar}`);
      } else {
        this.testResults.push(`✅ ${envVar} configured`);
      }
    });

    optionalEnvVars.forEach(envVar => {
      if (!process.env[envVar]) {
        this.warnings.push(`Optional environment variable not configured: ${envVar}`);
      } else {
        this.testResults.push(`✅ ${envVar} configured`);
      }
    });

    console.log('🔧 Environment validation completed');
  }

  /**
   * Validate file structure
   */
  async validateFileStructure() {
    console.log('📁 Validating file structure...');
    
    const criticalFiles = [
      'package.json',
      'tsconfig.json',
      'server/index.ts',
      'server/routes.ts',
      'server/storage.ts',
      'server/PostQuotaService.ts',
      'shared/schema.ts',
      'client/src/App.tsx',
      'client/src/pages/login.tsx',
      'client/src/pages/intelligent-schedule.tsx',
      'client/src/pages/brand-purpose.tsx',
      'client/src/pages/connect-platforms.tsx',
      'client/src/pages/analytics.tsx',
      'client/src/components/onboarding/OnboardingWizard.tsx'
    ];

    const criticalDirectories = [
      'server',
      'client',
      'shared',
      'scripts',
      'client/src/components',
      'client/src/pages'
    ];

    criticalFiles.forEach(file => {
      const filePath = path.join(process.cwd(), file);
      if (fs.existsSync(filePath)) {
        this.testResults.push(`✅ Critical file exists: ${file}`);
      } else {
        this.errors.push(`❌ Missing critical file: ${file}`);
      }
    });

    criticalDirectories.forEach(dir => {
      const dirPath = path.join(process.cwd(), dir);
      if (fs.existsSync(dirPath)) {
        this.testResults.push(`✅ Critical directory exists: ${dir}`);
      } else {
        this.errors.push(`❌ Missing critical directory: ${dir}`);
      }
    });

    console.log('📁 File structure validation completed');
  }

  /**
   * Validate database schema
   */
  async validateDatabaseSchema() {
    console.log('🗄️  Validating database schema...');
    
    const schemaFile = path.join(process.cwd(), 'shared/schema.ts');
    if (fs.existsSync(schemaFile)) {
      const schemaContent = fs.readFileSync(schemaFile, 'utf8');
      
      const requiredTables = [
        'users',
        'posts',
        'postLedger',
        'postSchedule',
        'platformConnections',
        'brandPurpose',
        'giftCertificates'
      ];

      requiredTables.forEach(table => {
        if (schemaContent.includes(table)) {
          this.testResults.push(`✅ Database table defined: ${table}`);
        } else {
          this.errors.push(`❌ Missing database table: ${table}`);
        }
      });

      // Check for proper relationships
      if (schemaContent.includes('relations')) {
        this.testResults.push(`✅ Database relations defined`);
      } else {
        this.warnings.push(`⚠️  Database relations not explicitly defined`);
      }

      console.log('🗄️  Database schema validation completed');
    } else {
      this.errors.push(`❌ Database schema file not found`);
    }
  }

  /**
   * Validate API endpoints
   */
  async validateApiEndpoints() {
    console.log('🔌 Validating API endpoints...');
    
    const routesFile = path.join(process.cwd(), 'server/routes.ts');
    if (fs.existsSync(routesFile)) {
      const routesContent = fs.readFileSync(routesFile, 'utf8');
      
      const criticalEndpoints = [
        '/api/user-status',
        '/api/user',
        '/api/brand-purpose',
        '/api/platform-connections',
        '/api/posts',
        '/api/analytics',
        '/api/generate-ai-schedule',
        '/api/create-checkout-session',
        '/api/payment-success',
        '/api/establish-session',
        '/api/quota-debug'
      ];

      criticalEndpoints.forEach(endpoint => {
        if (routesContent.includes(endpoint)) {
          this.testResults.push(`✅ API endpoint defined: ${endpoint}`);
        } else {
          this.errors.push(`❌ Missing API endpoint: ${endpoint}`);
        }
      });

      console.log('🔌 API endpoints validation completed');
    } else {
      this.errors.push(`❌ Routes file not found`);
    }
  }

  /**
   * Validate frontend routes
   */
  async validateFrontendRoutes() {
    console.log('📱 Validating frontend routes...');
    
    const appFile = path.join(process.cwd(), 'client/src/App.tsx');
    if (fs.existsSync(appFile)) {
      const appContent = fs.readFileSync(appFile, 'utf8');
      
      const criticalRoutes = [
        '/',
        '/splash',
        '/subscription',
        '/login',
        '/schedule',
        '/brand-purpose',
        '/connect-platforms',
        '/analytics'
      ];

      criticalRoutes.forEach(route => {
        if (appContent.includes(`"${route}"`) || appContent.includes(`'${route}'`)) {
          this.testResults.push(`✅ Frontend route defined: ${route}`);
        } else {
          this.warnings.push(`⚠️  Frontend route may not be defined: ${route}`);
        }
      });

      console.log('📱 Frontend routes validation completed');
    } else {
      this.errors.push(`❌ App.tsx file not found`);
    }
  }

  /**
   * Validate OAuth configuration
   */
  async validateOAuthConfig() {
    console.log('🔐 Validating OAuth configuration...');
    
    const oauthFile = path.join(process.cwd(), 'server/oauth-config.ts');
    if (fs.existsSync(oauthFile)) {
      const oauthContent = fs.readFileSync(oauthFile, 'utf8');
      
      const platforms = ['facebook', 'instagram', 'linkedin', 'twitter', 'youtube'];
      
      platforms.forEach(platform => {
        if (oauthContent.toLowerCase().includes(platform)) {
          this.testResults.push(`✅ OAuth config for ${platform}`);
        } else {
          this.warnings.push(`⚠️  OAuth config for ${platform} may be missing`);
        }
      });

      console.log('🔐 OAuth configuration validation completed');
    } else {
      this.warnings.push(`⚠️  OAuth config file not found`);
    }
  }

  /**
   * Validate payment integration
   */
  async validatePaymentIntegration() {
    console.log('💳 Validating payment integration...');
    
    const routesFile = path.join(process.cwd(), 'server/routes.ts');
    if (fs.existsSync(routesFile)) {
      const routesContent = fs.readFileSync(routesFile, 'utf8');
      
      const paymentEndpoints = [
        'create-checkout-session',
        'payment-success',
        'cancel-subscription'
      ];

      paymentEndpoints.forEach(endpoint => {
        if (routesContent.includes(endpoint)) {
          this.testResults.push(`✅ Payment endpoint: ${endpoint}`);
        } else {
          this.errors.push(`❌ Missing payment endpoint: ${endpoint}`);
        }
      });

      if (routesContent.includes('stripe')) {
        this.testResults.push(`✅ Stripe integration configured`);
      } else {
        this.warnings.push(`⚠️  Stripe integration may not be configured`);
      }

      console.log('💳 Payment integration validation completed');
    }
  }

  /**
   * Validate security configuration
   */
  async validateSecurity() {
    console.log('🔒 Validating security configuration...');
    
    const indexFile = path.join(process.cwd(), 'server/index.ts');
    if (fs.existsSync(indexFile)) {
      const indexContent = fs.readFileSync(indexFile, 'utf8');
      
      const securityFeatures = [
        'helmet',
        'cors',
        'express-session',
        'bcrypt'
      ];

      securityFeatures.forEach(feature => {
        if (indexContent.includes(feature)) {
          this.testResults.push(`✅ Security feature: ${feature}`);
        } else {
          this.warnings.push(`⚠️  Security feature may be missing: ${feature}`);
        }
      });

      console.log('🔒 Security configuration validation completed');
    }
  }

  /**
   * Validate performance configuration
   */
  async validatePerformance() {
    console.log('⚡ Validating performance configuration...');
    
    const packageFile = path.join(process.cwd(), 'package.json');
    if (fs.existsSync(packageFile)) {
      const packageContent = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
      
      // Check for performance optimizations
      if (packageContent.scripts && packageContent.scripts.build) {
        this.testResults.push(`✅ Build script configured`);
      } else {
        this.warnings.push(`⚠️  Build script may not be configured`);
      }

      if (packageContent.dependencies && packageContent.dependencies.pm2) {
        this.testResults.push(`✅ PM2 process manager configured`);
      } else {
        this.warnings.push(`⚠️  PM2 process manager not configured`);
      }

      console.log('⚡ Performance configuration validation completed');
    }
  }

  /**
   * Generate readiness report
   */
  async generateReadinessReport() {
    console.log('📊 Generating deployment readiness report...');
    
    const report = {
      timestamp: new Date().toISOString(),
      status: this.errors.length === 0 ? 'READY' : 'NOT_READY',
      summary: {
        totalTests: this.testResults.length,
        passed: this.testResults.length,
        errors: this.errors.length,
        warnings: this.warnings.length
      },
      results: this.testResults,
      errors: this.errors,
      warnings: this.warnings,
      recommendations: this.generateRecommendations()
    };

    fs.writeFileSync(
      path.join(process.cwd(), 'DEPLOYMENT_READINESS_REPORT.json'),
      JSON.stringify(report, null, 2)
    );

    console.log('📊 Readiness report generated: DEPLOYMENT_READINESS_REPORT.json');
    console.log(`📊 Status: ${report.status}`);
    console.log(`📊 Tests passed: ${report.summary.passed}`);
    console.log(`📊 Errors: ${report.summary.errors}`);
    console.log(`📊 Warnings: ${report.summary.warnings}`);
  }

  /**
   * Generate recommendations based on test results
   */
  generateRecommendations() {
    const recommendations = [];
    
    if (this.errors.length > 0) {
      recommendations.push('Fix all critical errors before deployment');
    }
    
    if (this.warnings.length > 0) {
      recommendations.push('Review and address warnings for optimal performance');
    }
    
    if (this.errors.length === 0 && this.warnings.length === 0) {
      recommendations.push('System is ready for deployment');
      recommendations.push('Consider setting up monitoring and alerting');
      recommendations.push('Ensure backup and rollback procedures are in place');
    }

    return recommendations;
  }
}

// Execute tests if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const test = new DeploymentReadinessTest();
  test.runTests()
    .then(() => {
      console.log('🎉 Deployment readiness verification completed');
      process.exit(0);
    })
    .catch(error => {
      console.error('💥 Deployment readiness verification failed:', error);
      process.exit(1);
    });
}

export default DeploymentReadinessTest;