/**
 * User Feedback Service for TheAgencyIQ
 * Handles feedback collection, categorization, and integration with content optimization
 */

import { storage } from './storage.js';

export interface UserFeedback {
  id?: number;
  userId: number;
  feedbackType: 'content_quality' | 'platform_performance' | 'feature_request' | 'bug_report' | 'general';
  message: string;
  platform?: string;
  postId?: number;
  rating?: number; // 1-5 scale
  metadata?: {
    userAgent?: string;
    timestamp?: string;
    sessionId?: string;
    contentGenerated?: boolean;
    platformConnections?: string[];
  };
  status: 'new' | 'reviewed' | 'implemented' | 'resolved';
  createdAt?: Date;
  resolvedAt?: Date;
}

export interface FeedbackAnalytics {
  totalFeedback: number;
  averageRating: number;
  topIssues: { type: string; count: number }[];
  platformPerformance: { platform: string; avgRating: number }[];
  recentTrends: { date: string; count: number; avgRating: number }[];
}

class UserFeedbackService {
  private feedbackCache: Map<number, UserFeedback[]> = new Map();
  private analyticsCache: FeedbackAnalytics | null = null;
  private cacheExpiry: number = 0;
  private readonly CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

  /**
   * Submit new user feedback
   */
  async submitFeedback(feedback: Omit<UserFeedback, 'id' | 'createdAt' | 'status'>): Promise<{ success: boolean; feedbackId?: number; error?: string }> {
    try {
      // Validate required fields
      if (!feedback.userId || !feedback.feedbackType || !feedback.message) {
        return { success: false, error: 'Missing required fields: userId, feedbackType, message' };
      }

      // Create feedback record
      const feedbackData: UserFeedback = {
        ...feedback,
        status: 'new',
        createdAt: new Date(),
        metadata: {
          ...feedback.metadata,
          timestamp: new Date().toISOString()
        }
      };

      // Store in database (simulated - extend storage interface as needed)
      const feedbackId = await this.storeFeedback(feedbackData);
      
      // Clear cache to ensure fresh data
      this.clearCache();
      
      // Process feedback for immediate improvements
      await this.processFeedbackForImprovements(feedbackData);

      console.log(`✅ Feedback submitted successfully: ID ${feedbackId}, Type: ${feedback.feedbackType}`);
      
      return { success: true, feedbackId };
    } catch (error) {
      console.error('❌ Error submitting feedback:', error);
      return { success: false, error: 'Failed to submit feedback' };
    }
  }

  /**
   * Get feedback analytics for dashboard
   */
  async getFeedbackAnalytics(userId?: number): Promise<FeedbackAnalytics> {
    try {
      // Return cached analytics if still valid
      if (this.analyticsCache && Date.now() < this.cacheExpiry) {
        return this.analyticsCache;
      }

      const feedback = await this.getAllFeedback(userId);
      
      const analytics: FeedbackAnalytics = {
        totalFeedback: feedback.length,
        averageRating: this.calculateAverageRating(feedback),
        topIssues: this.getTopIssues(feedback),
        platformPerformance: this.getPlatformPerformance(feedback),
        recentTrends: this.getRecentTrends(feedback)
      };

      // Cache the results
      this.analyticsCache = analytics;
      this.cacheExpiry = Date.now() + this.CACHE_DURATION;

      return analytics;
    } catch (error) {
      console.error('❌ Error getting feedback analytics:', error);
      return {
        totalFeedback: 0,
        averageRating: 0,
        topIssues: [],
        platformPerformance: [],
        recentTrends: []
      };
    }
  }

  /**
   * Get feedback by user ID with pagination
   */
  async getUserFeedback(userId: number, page: number = 1, limit: number = 10): Promise<{ feedback: UserFeedback[]; total: number; hasMore: boolean }> {
    try {
      const allFeedback = await this.getAllFeedback(userId);
      const startIndex = (page - 1) * limit;
      const endIndex = startIndex + limit;
      
      const feedback = allFeedback
        .sort((a, b) => (b.createdAt?.getTime() || 0) - (a.createdAt?.getTime() || 0))
        .slice(startIndex, endIndex);

      return {
        feedback,
        total: allFeedback.length,
        hasMore: endIndex < allFeedback.length
      };
    } catch (error) {
      console.error('❌ Error getting user feedback:', error);
      return { feedback: [], total: 0, hasMore: false };
    }
  }

  /**
   * Process feedback for immediate content improvements
   */
  private async processFeedbackForImprovements(feedback: UserFeedback): Promise<void> {
    try {
      if (feedback.feedbackType === 'content_quality' && feedback.platform && feedback.rating && feedback.rating < 3) {
        // Low rating for content - trigger content optimization
        console.log(`🔄 Processing low-rating content feedback for ${feedback.platform}: ${feedback.message}`);
        
        // Could integrate with SEO service or content generation improvements
        await this.optimizeContentBasedOnFeedback(feedback);
      }

      if (feedback.feedbackType === 'platform_performance' && feedback.platform) {
        // Platform performance issue - log for monitoring
        console.log(`⚠️ Platform performance issue reported for ${feedback.platform}: ${feedback.message}`);
      }

      if (feedback.feedbackType === 'feature_request') {
        // Feature request - categorize for development backlog
        console.log(`💡 Feature request received: ${feedback.message}`);
      }
    } catch (error) {
      console.error('❌ Error processing feedback for improvements:', error);
    }
  }

  /**
   * Optimize content generation based on user feedback
   */
  private async optimizeContentBasedOnFeedback(feedback: UserFeedback): Promise<void> {
    try {
      if (!feedback.platform || !feedback.message) return;

      // Extract insights from feedback message
      const insights = this.extractContentInsights(feedback.message);
      
      // Update content optimization parameters (could extend to integrate with grok.ts)
      console.log(`🎯 Content optimization insights for ${feedback.platform}:`, insights);
      
      // Future enhancement: Update AI generation parameters based on feedback patterns
    } catch (error) {
      console.error('❌ Error optimizing content based on feedback:', error);
    }
  }

  /**
   * Extract actionable insights from feedback text
   */
  private extractContentInsights(message: string): { keywords: string[]; sentiment: string; suggestions: string[] } {
    const lowercaseMessage = message.toLowerCase();
    
    // Simple keyword extraction (could be enhanced with NLP)
    const keywords = [];
    if (lowercaseMessage.includes('boring')) keywords.push('engagement');
    if (lowercaseMessage.includes('too long')) keywords.push('brevity');
    if (lowercaseMessage.includes('unclear')) keywords.push('clarity');
    if (lowercaseMessage.includes('irrelevant')) keywords.push('targeting');

    // Simple sentiment analysis
    const sentiment = lowercaseMessage.includes('good') || lowercaseMessage.includes('great') || lowercaseMessage.includes('love') 
      ? 'positive' 
      : lowercaseMessage.includes('bad') || lowercaseMessage.includes('terrible') || lowercaseMessage.includes('hate')
      ? 'negative'
      : 'neutral';

    // Generate suggestions
    const suggestions = [];
    if (keywords.includes('engagement')) suggestions.push('Increase interactive elements');
    if (keywords.includes('brevity')) suggestions.push('Reduce content length');
    if (keywords.includes('clarity')) suggestions.push('Simplify language');
    if (keywords.includes('targeting')) suggestions.push('Improve audience targeting');

    return { keywords, sentiment, suggestions };
  }

  /**
   * Helper methods for analytics
   */
  private calculateAverageRating(feedback: UserFeedback[]): number {
    const ratingsOnly = feedback.filter(f => f.rating).map(f => f.rating!);
    return ratingsOnly.length > 0 ? ratingsOnly.reduce((sum, rating) => sum + rating, 0) / ratingsOnly.length : 0;
  }

  private getTopIssues(feedback: UserFeedback[]): { type: string; count: number }[] {
    const issueCounts: Record<string, number> = {};
    feedback.forEach(f => {
      issueCounts[f.feedbackType] = (issueCounts[f.feedbackType] || 0) + 1;
    });
    
    return Object.entries(issueCounts)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }

  private getPlatformPerformance(feedback: UserFeedback[]): { platform: string; avgRating: number }[] {
    const platformRatings: Record<string, number[]> = {};
    
    feedback.forEach(f => {
      if (f.platform && f.rating) {
        if (!platformRatings[f.platform]) platformRatings[f.platform] = [];
        platformRatings[f.platform].push(f.rating);
      }
    });

    return Object.entries(platformRatings)
      .map(([platform, ratings]) => ({
        platform,
        avgRating: ratings.reduce((sum, rating) => sum + rating, 0) / ratings.length
      }))
      .sort((a, b) => b.avgRating - a.avgRating);
  }

  private getRecentTrends(feedback: UserFeedback[]): { date: string; count: number; avgRating: number }[] {
    const last7Days = Array.from({ length: 7 }, (_, i) => {
      const date = new Date();
      date.setDate(date.getDate() - i);
      return date.toISOString().split('T')[0];
    }).reverse();

    return last7Days.map(date => {
      const dayFeedback = feedback.filter(f => 
        f.createdAt && f.createdAt.toISOString().split('T')[0] === date
      );
      
      const ratings = dayFeedback.filter(f => f.rating).map(f => f.rating!);
      const avgRating = ratings.length > 0 ? ratings.reduce((sum, r) => sum + r, 0) / ratings.length : 0;

      return {
        date,
        count: dayFeedback.length,
        avgRating
      };
    });
  }

  /**
   * Storage operations (extend as needed)
   */
  private async storeFeedback(feedback: UserFeedback): Promise<number> {
    // Simulate storage operation - extend storage interface to include feedback table
    const mockId = Date.now() + Math.floor(Math.random() * 1000);
    console.log(`💾 Storing feedback: ${feedback.feedbackType} from user ${feedback.userId}`);
    return mockId;
  }

  private async getAllFeedback(userId?: number): Promise<UserFeedback[]> {
    // Simulate getting feedback from storage
    // In real implementation, this would query the database
    return [];
  }

  private clearCache(): void {
    this.feedbackCache.clear();
    this.analyticsCache = null;
    this.cacheExpiry = 0;
  }
}

export const userFeedbackService = new UserFeedbackService();