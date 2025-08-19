export interface Usage {
  remainingPosts: number;
  totalAllocation: number;
  subscriptionPlan: string;
  usedPosts: number;
  usagePercentage: number;
}
export interface PlatformConnection {
  platform: string;
  expiresAt: Date;
}
export interface LearningInsights {
  insights: {
    projectedImprovement: number;
    recommendations: string[];
  };
}
export interface GrowthData {
  insights: {
    currentPeriod: { reachGrowth: number; engagementGrowth: number; conversionRate: number };
    growth: { reachGrowth: number; engagementGrowth: number; conversionRate: number };
    recommendations: string[];
  };
}
export interface AudienceData {
  insights: {
    demographics: { [key: string]: number };
    geographicReach: { [key: string]: number };
    interests: string[];
    optimalContentTypes: string[];
  };
}
export interface User {
  subscriptionActive: boolean;
  subscriptionPlan: string;
  id: number;
}
export interface YearlyAnalytics {
  monthlyPerformance: { posts: number; conversions: number }[];
}