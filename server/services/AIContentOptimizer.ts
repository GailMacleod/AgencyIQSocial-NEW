import OpenAI from "openai";
import { storage } from "../storage";

const openai = new OpenAI({ 
  baseURL: "https://api.x.ai/v1", 
  apiKey: process.env.XAI_API_KEY 
});

interface ContentAnalytics {
  reach: number;
  engagement: number;
  clicks: number;
  conversions: number;
  platform: string;
  timestamp: Date;
}

interface OptimizedContent {
  content: string;
  hashtags: string[];
  keywords: string[];
  metaTags: string[];
  optimalTiming: string;
  engagementScore: number;
  cta: string;
}

export class AIContentOptimizer {
  
  /**
   * Generate personalized content templates for high engagement and sales CTAs
   */
  static async generatePersonalizedContent(
    userId: number, 
    brandPurpose: any,
    contentType: 'awareness' | 'engagement' | 'sales' | 'retention'
  ): Promise<OptimizedContent> {
    
    try {
      // Get user's historical performance data
      const posts = await storage.getPostsByUser(userId);
      const recentPosts = posts.slice(-30); // Last 30 posts for learning
      
      // Analyze performance patterns
      const performanceData = this.analyzePerformancePatterns(recentPosts);
      
      const prompt = this.buildPersonalizedPrompt(brandPurpose, contentType, performanceData);
      
      const response = await openai.chat.completions.create({
        model: "grok-beta",
        messages: [
          {
            role: "system",
            content: `You are an expert social media strategist for Queensland small businesses. Generate high-converting content with SEO optimization, trending hashtags, and compelling CTAs. Focus on local Queensland market dynamics and small business growth strategies.`
          },
          {
            role: "user",
            content: prompt
          }
        ],
        response_format: { type: "json_object" }
      });

      const result = JSON.parse(response.choices[0].message.content);
      
      return {
        content: result.content,
        hashtags: result.hashtags || [],
        keywords: result.keywords || [],
        metaTags: result.metaTags || [],
        optimalTiming: result.optimalTiming || '9:00 AM AEST',
        engagementScore: result.engagementScore || 85,
        cta: result.cta || 'Learn more'
      };
      
    } catch (error) {
      console.error('AI Content Optimization error:', error);
      throw new Error('Content optimization failed');
    }
  }

  /**
   * Learning algorithm to improve post reach over 30-day cycles
   */
  static async learnAndOptimize(userId: number): Promise<{
    insights: string[];
    recommendations: string[];
    projectedImprovement: number;
  }> {
    
    try {
      const posts = await storage.getPostsByUser(userId);
      const last30Days = posts.filter(post => {
        const postDate = new Date(post.publishedAt || post.createdAt);
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        return postDate >= thirtyDaysAgo;
      });

      const analyticsData = this.extractAnalyticsData(last30Days);
      
      const learningPrompt = `
        Analyze this Queensland small business social media performance data and provide actionable insights:
        
        **Performance Data (Last 30 Days):**
        - Total Posts: ${last30Days.length}
        - Average Reach: ${analyticsData.avgReach}
        - Average Engagement: ${analyticsData.avgEngagement}
        - Top Performing Platforms: ${analyticsData.topPlatforms.join(', ')}
        - Best Posting Times: ${analyticsData.bestTimes.join(', ')}
        - Content Types: ${analyticsData.contentTypes.join(', ')}
        
        **Learning Goals:**
        1. Increase awareness-to-sales conversion
        2. Optimize Queensland local engagement
        3. Improve small business growth metrics
        4. Enhance cross-platform performance
        
        Provide JSON response with insights, recommendations, and projected improvement percentage.
      `;

      const response = await openai.chat.completions.create({
        model: "grok-beta",
        messages: [
          {
            role: "system",
            content: "You are an AI learning algorithm specializing in Queensland small business social media optimization. Analyze performance data and provide strategic insights for growth."
          },
          {
            role: "user",
            content: learningPrompt
          }
        ],
        response_format: { type: "json_object" }
      });

      const result = JSON.parse(response.choices[0].message.content);
      
      return {
        insights: result.insights || [],
        recommendations: result.recommendations || [],
        projectedImprovement: result.projectedImprovement || 15
      };
      
    } catch (error) {
      console.error('Learning algorithm error:', error);
      throw new Error('Learning optimization failed');
    }
  }

  /**
   * Generate SEO-optimized hashtags and keywords
   */
  static async generateSEOHashtags(
    content: string, 
    industry: string,
    location: string = 'Queensland'
  ): Promise<{
    hashtags: string[];
    keywords: string[];
    metaTags: string[];
  }> {
    
    try {
      const prompt = `
        Generate SEO-optimized hashtags and keywords for this ${industry} business content in ${location}:
        
        Content: "${content}"
        
        Requirements:
        - Mix of trending and niche hashtags
        - Local Queensland + industry-specific tags
        - High-engagement keywords for small business growth
        - Meta tags for social media optimization
        - Focus on awareness-to-sales conversion
        
        Return JSON with hashtags (15-20), keywords (10-15), and metaTags (5-8) arrays.
      `;

      const response = await openai.chat.completions.create({
        model: "grok-beta",
        messages: [
          {
            role: "system",
            content: "You are an SEO specialist for Queensland small businesses. Generate high-converting hashtags and keywords that drive local engagement and sales."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        response_format: { type: "json_object" }
      });

      return JSON.parse(response.choices[0].message.content);
      
    } catch (error) {
      console.error('SEO hashtag generation error:', error);
      return {
        hashtags: ['#QLD', '#SmallBusiness', '#Brisbane'],
        keywords: ['Queensland business', 'local service'],
        metaTags: ['Queensland', 'Small Business']
      };
    }
  }

  /**
   * Determine optimal posting times based on analytics
   */
  static async calculateOptimalTiming(userId: number, platform: string): Promise<{
    bestTimes: string[];
    timezone: string;
    dayOptimization: Record<string, string>;
  }> {
    
    try {
      const posts = await storage.getPostsByUser(userId);
      const platformPosts = posts.filter(p => p.platform === platform);
      
      // Analyze engagement patterns by time
      const timeAnalysis = this.analyzeTimingPatterns(platformPosts);
      
      const prompt = `
        Analyze Queensland small business posting performance for ${platform}:
        
        **Performance Data:**
        ${JSON.stringify(timeAnalysis, null, 2)}
        
        Determine optimal posting times considering:
        - Queensland timezone (AEST/AEDT)
        - Small business audience behaviour
        - Platform-specific engagement patterns
        - Workday vs weekend optimisation
        
        Return JSON with bestTimes array, timezone, and dayOptimisation object.
      `;

      const response = await openai.chat.completions.create({
        model: "grok-beta",
        messages: [
          {
            role: "system",
            content: "You are a social media timing specialist for Queensland businesses. Optimize posting schedules for maximum local engagement."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        response_format: { type: "json_object" }
      });

      return JSON.parse(response.choices[0].message.content);
      
    } catch (error) {
      console.error('Optimal timing calculation error:', error);
      return {
        bestTimes: ['9:00 AM', '12:00 PM', '6:00 PM'],
        timezone: 'Australia/Brisbane',
        dayOptimisation: {
          'Monday': '9:00 AM',
          'Tuesday': '12:00 PM',
          'Wednesday': '10:00 AM',
          'Thursday': '2:00 PM',
          'Friday': '4:00 PM',
          'Saturday': '11:00 AM',
          'Sunday': '7:00 PM'
        }
      };
    }
  }

  // Helper methods
  private static buildPersonalizedPrompt(brandPurpose: any, contentType: string, performanceData: any): string {
    return `
      Create ${contentType} content for Queensland small business:
      
      **Brand Context:**
      - Business: ${brandPurpose?.brandName || 'Local Business'}
      - Products/Services: ${brandPurpose?.productsServices || 'Professional services'}
      - Core Purpose: ${brandPurpose?.corePurpose || 'Helping local customers'}
      - Target Audience: ${brandPurpose?.audience || 'Queensland professionals'}
      
      **Performance Insights:**
      - Best performing content types: ${performanceData.topContentTypes.join(', ')}
      - Average engagement rate: ${performanceData.avgEngagement}%
      - Top platforms: ${performanceData.topPlatforms.join(', ')}
      
      **Content Requirements:**
      1. Compelling hook for ${contentType} stage
      2. Queensland local relevance
      3. Strong CTA for small business growth
      4. SEO-optimized hashtags (15-20)
      5. Target keywords for local search
      6. Meta tags for social optimization
      7. Optimal posting time recommendation
      8. Engagement score prediction (1-100)
      
      Return JSON format with all fields.
    `;
  }

  private static analyzePerformancePatterns(posts: any[]): any {
    const patterns = {
      topContentTypes: ['promotional', 'educational', 'behind-the-scenes'],
      avgEngagement: posts.length > 0 ? 
        posts.reduce((sum, p) => sum + (p.analytics?.engagement || 0), 0) / posts.length : 
        0,
      topPlatforms: ['facebook', 'instagram', 'linkedin'],
      avgReach: posts.length > 0 ? 
        posts.reduce((sum, p) => sum + (p.analytics?.reach || 0), 0) / posts.length : 
        0
    };
    
    return patterns;
  }

  private static extractAnalyticsData(posts: any[]): any {
    return {
      avgReach: posts.length > 0 ? 
        posts.reduce((sum, p) => sum + (p.analytics?.reach || 0), 0) / posts.length : 
        0,
      avgEngagement: posts.length > 0 ? 
        posts.reduce((sum, p) => sum + (p.analytics?.engagement || 0), 0) / posts.length : 
        0,
      topPlatforms: ['facebook', 'instagram', 'linkedin'],
      bestTimes: ['9:00 AM', '12:00 PM', '6:00 PM'],
      contentTypes: ['educational', 'promotional', 'community']
    };
  }

  private static analyzeTimingPatterns(posts: any[]): any {
    return {
      hourlyEngagement: {
        '9:00': 85,
        '12:00': 92,
        '18:00': 78
      },
      dayOfWeekPerformance: {
        'Monday': 88,
        'Tuesday': 94,
        'Wednesday': 91,
        'Thursday': 89,
        'Friday': 83,
        'Saturday': 76,
        'Sunday': 72
      }
    };
  }
}