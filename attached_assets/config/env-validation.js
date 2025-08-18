/**
 * Environment Variable Validation
 * Ensures critical environment variables are properly configured
 */

import Joi from 'joi';

const envSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  
  SESSION_SECRET: Joi.string()
    .min(32)
    .required()
    .messages({
      'any.required': 'SESSION_SECRET is required for secure sessions',
      'string.min': 'SESSION_SECRET must be at least 32 characters for security'
    }),
  
  DATABASE_URL: Joi.string()
    .uri()
    .required()
    .messages({
      'any.required': 'DATABASE_URL is required for PostgreSQL connection',
      'string.uri': 'DATABASE_URL must be a valid PostgreSQL connection string'
    }),
  
  GOOGLE_AI_STUDIO_KEY: Joi.string()
    .optional()
    .messages({
      'string.base': 'GOOGLE_AI_STUDIO_KEY must be a valid API key'
    }),
  
  OPENAI_API_KEY: Joi.string()
    .optional()
    .messages({
      'string.base': 'OPENAI_API_KEY must be a valid API key'
    }),
  
  // OAuth Environment Variables (optional but recommended)
  FACEBOOK_APP_ID: Joi.string().optional(),
  FACEBOOK_APP_SECRET: Joi.string().optional(),
  TWITTER_CONSUMER_KEY: Joi.string().optional(),
  TWITTER_CONSUMER_SECRET: Joi.string().optional(),
  GOOGLE_CLIENT_ID: Joi.string().optional(),
  GOOGLE_CLIENT_SECRET: Joi.string().optional(),
  LINKEDIN_CLIENT_ID: Joi.string().optional(),
  LINKEDIN_CLIENT_SECRET: Joi.string().optional(),
  
  // Replit Environment (automatically provided)
  REPL_ID: Joi.string().optional(),
  REPLIT_DOMAINS: Joi.string().optional(),
  
}).unknown(); // Allow other environment variables

export function validateEnvironment() {
  console.log('🔍 Validating environment configuration...');
  
  const { error, value } = envSchema.validate(process.env, {
    abortEarly: false,
    stripUnknown: false
  });
  
  if (error) {
    console.error('❌ Environment validation failed:');
    error.details.forEach(detail => {
      console.error(`   • ${detail.message}`);
    });
    
    // In production, fail fast for critical errors
    if (process.env.NODE_ENV === 'production') {
      console.error('💥 Critical environment errors in production - exiting');
      process.exit(1);
    } else {
      console.warn('⚠️ Environment warnings in development - continuing with defaults');
    }
  } else {
    console.log('✅ Environment validation passed');
  }
  
  // Validate OAuth configuration completeness
  validateOAuthConfiguration();
  
  return value;
}

function validateOAuthConfiguration() {
  const oauthPlatforms = [
    { name: 'Facebook', id: 'FACEBOOK_APP_ID', secret: 'FACEBOOK_APP_SECRET' },
    { name: 'Twitter', id: 'TWITTER_CONSUMER_KEY', secret: 'TWITTER_CONSUMER_SECRET' },
    { name: 'Google', id: 'GOOGLE_CLIENT_ID', secret: 'GOOGLE_CLIENT_SECRET' },
    { name: 'LinkedIn', id: 'LINKEDIN_CLIENT_ID', secret: 'LINKEDIN_CLIENT_SECRET' }
  ];
  
  const configuredPlatforms = [];
  const missingPlatforms = [];
  
  oauthPlatforms.forEach(platform => {
    if (process.env[platform.id] && process.env[platform.secret]) {
      configuredPlatforms.push(platform.name);
    } else {
      missingPlatforms.push(platform.name);
    }
  });
  
  console.log(`🔐 OAuth Configuration Status:`);
  if (configuredPlatforms.length > 0) {
    console.log(`   ✅ Configured: ${configuredPlatforms.join(', ')}`);
  }
  if (missingPlatforms.length > 0) {
    console.log(`   ⚠️ Missing: ${missingPlatforms.join(', ')}`);
    console.log(`   💡 Add OAuth credentials to enable social media posting`);
  }
}

export function getSecureDefaults() {
  return {
    SESSION_SECRET: process.env.SESSION_SECRET || (() => {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('SESSION_SECRET must be set in production');
      }
      console.warn('⚠️ Using fallback SESSION_SECRET in development');
      return 'theagencyiq-dev-secret-change-in-production';
    })(),
    
    CORS_ORIGIN: process.env.NODE_ENV === 'production' 
      ? process.env.REPLIT_DOMAINS?.split(',').map(domain => `https://${domain}`) || 'https://your-app.replit.app'
      : true, // Allow all origins in development
      
    RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15 minutes
    RATE_LIMIT_MAX: process.env.NODE_ENV === 'production' ? 100 : 1000,
    
    LOG_LEVEL: process.env.NODE_ENV === 'production' ? 'combined' : 'dev'
  };
}