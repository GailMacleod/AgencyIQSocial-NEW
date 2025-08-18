import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/api";
import { TrendingUp, TrendingDown, Target, Users, MessageCircle, Eye, BarChart3 } from "lucide-react";
import { format, startOfMonth, endOfMonth } from "date-fns";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";
import BackButton from "@/components/back-button";
import { MetaPixelTracker } from "@/lib/meta-pixel";
import MetaPixelStatus from "@/components/meta-pixel-status";
import OnboardingWizard from "@/components/onboarding/OnboardingWizard";

interface AnalyticsData {
  totalPosts: number;
  targetPosts: number;
  reach: number;
  targetReach: number;
  engagement: number;
  targetEngagement: number;
  conversions: number;
  targetConversions: number;
  brandAwareness: number;
  targetBrandAwareness: number;
  platformBreakdown: {
    platform: string;
    posts: number;
    reach: number;
    engagement: number;
    performance: number;
    isPlaceholder?: boolean;
  }[];
  monthlyTrends: {
    month: string;
    posts: number;
    reach: number;
    engagement: number;
  }[];
  goalProgress: {
    growth: { current: number; target: number; percentage: number };
    efficiency: { current: number; target: number; percentage: number };
    reach: { current: number; target: number; percentage: number };
    engagement: { current: number; target: number; percentage: number };
  };
  hasRealData?: boolean;
  connectedPlatforms?: string[];
}

interface MetricCard {
  title: string;
  current: number;
  target: number;
  unit: string;
  icon: React.ReactNode;
  trend: "up" | "down" | "stable";
  trendValue: number;
}

export default function Analytics() {
  const [currentMonth] = useState(new Date());
  const [currentView, setCurrentView] = useState<'overview' | 'platforms' | 'trends'>('overview');
  const [touchStart, setTouchStart] = useState<number | null>(null);
  const [touchEnd, setTouchEnd] = useState<number | null>(null);

  // Swipe gesture handling for mobile
  const handleTouchStart = (e: React.TouchEvent) => {
    setTouchEnd(null);
    setTouchStart(e.targetTouches[0].clientX);
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    setTouchEnd(e.targetTouches[0].clientX);
  };

  const handleTouchEnd = () => {
    if (!touchStart || !touchEnd) return;
    
    const distance = touchStart - touchEnd;
    const isLeftSwipe = distance > 50;
    const isRightSwipe = distance < -50;

    if (isLeftSwipe) {
      // Swipe left - next view
      if (currentView === 'overview') setCurrentView('platforms');
      else if (currentView === 'platforms') setCurrentView('trends');
    }
    
    if (isRightSwipe) {
      // Swipe right - previous view
      if (currentView === 'trends') setCurrentView('platforms');
      else if (currentView === 'platforms') setCurrentView('overview');
    }
  };

  const { data: analytics, isLoading } = useQuery<AnalyticsData>({
    queryKey: ["/api/analytics"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: brandPurpose } = useQuery({
    queryKey: ["/api/brand-purpose"],
  });

  // Track analytics page view for Meta Pixel
  useEffect(() => {
    if (analytics) {
      // Track analytics view with performance data
      MetaPixelTracker.trackAnalyticsView('monthly', analytics.platformBreakdown?.map(p => p.platform) || []);
      
      // Track feature usage
      MetaPixelTracker.trackFeatureUsage('analytics_dashboard');
      
      // Track performance insights based on goal achievement
      const performanceLevel = analytics.totalPosts >= analytics.targetPosts ? 'high' : 
                             analytics.totalPosts >= (analytics.targetPosts * 0.7) ? 'medium' : 'low';
      
      MetaPixelTracker.trackCustomEvent('PerformanceReview', {
        performance_level: performanceLevel,
        posts_published: analytics.totalPosts,
        target_posts: analytics.targetPosts,
        reach_achieved: analytics.reach,
        conversion_rate: analytics.conversions / Math.max(analytics.reach, 1) * 100,
        platforms_connected: analytics.platformBreakdown?.length || 0
      });
    }
  }, [analytics]);

  // Check if we have real published data
  const hasRealData = analytics?.hasRealData || false;

  // Calculate performance metrics
  const getPerformanceColor = (current: number, target: number) => {
    const percentage = (current / target) * 100;
    if (percentage >= 90) return "text-[#3250fa]";
    if (percentage >= 70) return "text-yellow-600";
    return "text-red-600";
  };

  const getPerformanceStatus = (current: number, target: number) => {
    const percentage = (current / target) * 100;
    if (percentage >= 100) return "Exceeded";
    if (percentage >= 90) return "On Track";
    if (percentage >= 70) return "Needs Attention";
    return "Critical";
  };

  const metricCards: MetricCard[] = analytics ? [
    {
      title: "Posts Published",
      current: analytics.totalPosts,
      target: analytics.targetPosts,
      unit: "posts",
      icon: <BarChart3 className="w-5 h-5" />,
      trend: analytics.totalPosts > (analytics.targetPosts * 0.8) ? "up" : "down",
      trendValue: ((analytics.totalPosts / analytics.targetPosts) * 100) - 100
    },
    {
      title: "Total Reach",
      current: analytics.reach,
      target: analytics.targetReach,
      unit: "people",
      icon: <Eye className="w-5 h-5" />,
      trend: analytics.reach > analytics.targetReach ? "up" : "down",
      trendValue: ((analytics.reach / analytics.targetReach) * 100) - 100
    },
    {
      title: "Engagement Rate",
      current: analytics.engagement,
      target: analytics.targetEngagement,
      unit: "%",
      icon: <MessageCircle className="w-5 h-5" />,
      trend: analytics.engagement > analytics.targetEngagement ? "up" : "down",
      trendValue: analytics.engagement - analytics.targetEngagement
    },
    {
      title: "Lead Conversions",
      current: analytics.conversions,
      target: analytics.targetConversions,
      unit: "leads",
      icon: <Target className="w-5 h-5" />,
      trend: analytics.conversions > analytics.targetConversions ? "up" : "down",
      trendValue: ((analytics.conversions / analytics.targetConversions) * 100) - 100
    }
  ] : [];

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <MasterHeader showUserMenu={true} />
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin w-8 h-8 border-4 border-purple-600 border-t-transparent rounded-full"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <MasterHeader showUserMenu={true} />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <BackButton to="/schedule" label="Back to Schedule" />
        </div>
        
        {/* Progress Indicator */}
        <div className="text-center mb-8">
          <p className="text-sm text-gray-600">Step 4 of 4</p>
          <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
            <div className="bg-purple-600 h-2 rounded-full w-full"></div>
          </div>
        </div>

        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-heading font-light text-foreground mb-4">
            Performance Analytics
          </h1>
          <p className="text-gray-600 text-sm">
            Measuring outputs versus targets from your brand purpose strategy
          </p>
          <p className="text-gray-500 text-xs mt-2">
            {format(startOfMonth(currentMonth), 'MMMM yyyy')} performance overview
          </p>
        </div>

        {/* Key Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {metricCards.map((metric, index) => (
            <Card key={index} className="relative overflow-hidden">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {metric.icon}
                    <span className="text-sm font-medium text-gray-600">{metric.title}</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    {metric.trend === "up" ? (
                      <TrendingUp className="w-4 h-4 text-[#3250fa]" />
                    ) : (
                      <TrendingDown className="w-4 h-4 text-red-600" />
                    )}
                    <span className={`text-xs ${metric.trend === "up" ? "text-[#3250fa]" : "text-red-600"}`}>
                      {metric.trendValue > 0 ? "+" : ""}{metric.trendValue.toFixed(1)}%
                    </span>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-baseline justify-between">
                    <span className="text-2xl font-bold text-gray-900">
                      {metric.current.toLocaleString()}
                    </span>
                    <span className="text-sm text-gray-500">
                      / {metric.target.toLocaleString()} {metric.unit}
                    </span>
                  </div>
                  <Progress 
                    value={(metric.current / metric.target) * 100} 
                    className="h-2"
                  />
                  <div className="flex justify-between items-center">
                    <Badge 
                      variant="outline" 
                      className={`text-xs ${getPerformanceColor(metric.current, metric.target)}`}
                    >
                      {getPerformanceStatus(metric.current, metric.target)}
                    </Badge>
                    <span className="text-xs text-gray-500">
                      {((metric.current / metric.target) * 100).toFixed(1)}% complete
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Brand Purpose Goals Progress */}
        {analytics?.goalProgress && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="text-lg font-medium">Brand Purpose Goals Progress</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {Object.entries(analytics.goalProgress).map(([key, goal]) => (
                  <div key={key} className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium text-gray-700">{key} Goal</span>
                      <span className="text-xs text-gray-500">{goal.percentage}%</span>
                    </div>
                    <Progress value={goal.percentage} className="h-2" />
                    <div className="flex justify-between text-xs text-gray-500">
                      <span>{goal.current}</span>
                      <span>target: {goal.target}</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Platform Performance Breakdown */}
        {analytics?.platformBreakdown && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="text-lg font-medium">Platform Performance</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {analytics.platformBreakdown.map((platform) => (
                  <div key={platform.platform} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                    <div className="flex items-center space-x-4">
                      <div className="w-10 h-10 bg-purple-100 rounded-full flex items-center justify-center">
                        <span className="text-purple-700 font-medium text-sm lowercase">
                          {platform.platform.substring(0, 2)}
                        </span>
                      </div>
                      <div>
                        <h3 className="font-medium text-gray-900">{platform.platform}</h3>
                        <p className="text-sm text-gray-500">{platform.posts} posts published</p>
                      </div>
                    </div>
                    <div className="text-right space-y-1">
                      <div className="flex items-center space-x-4">
                        <div className="text-right">
                          <p className="text-sm font-medium text-gray-900">{platform.reach.toLocaleString()}</p>
                          <p className="text-xs text-gray-500">reach</p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm font-medium text-gray-900">{platform.engagement}%</p>
                          <p className="text-xs text-gray-500">engagement</p>
                        </div>
                        <Badge 
                          variant={platform.performance >= 90 ? "default" : platform.performance >= 70 ? "secondary" : "destructive"}
                          className=""
                        >
                          {platform.performance}% performance
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Meta Pixel Status Component */}
        <div className="mb-8">
          <MetaPixelStatus />
        </div>

        {/* Navigation to Yearly Analytics */}
        <div className="text-center mb-8">
          <Button
            onClick={() => window.location.href = '/yearly-analytics'}
            className="bg-purple-600 hover:bg-purple-700 text-white"
          >
            View Year-to-Date Performance
          </Button>
        </div>

        {/* Action Items */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg font-medium">Recommended Actions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {analytics && analytics.reach < analytics.targetReach && (
                <div className="flex items-start space-x-3 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <Target className="w-5 h-5 text-yellow-600 mt-0.5" />
                  <div>
                    <h4 className="font-medium text-yellow-800 lowercase">increase reach</h4>
                    <p className="text-sm text-yellow-700">
                      Consider posting during peak Queensland engagement hours and using location-based hashtags
                    </p>
                  </div>
                </div>
              )}
              {analytics && analytics.engagement < analytics.targetEngagement && (
                <div className="flex items-start space-x-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                  <MessageCircle className="w-5 h-5 text-blue-600 mt-0.5" />
                  <div>
                    <h4 className="font-medium text-blue-800 lowercase">boost engagement</h4>
                    <p className="text-sm text-blue-700">
                      Try asking questions and creating polls related to Queensland business challenges
                    </p>
                  </div>
                </div>
              )}
              {analytics && analytics.totalPosts < analytics.targetPosts && (
                <div className="flex items-start space-x-3 p-3 bg-purple-50 border border-purple-200 rounded-lg">
                  <BarChart3 className="w-5 h-5 text-purple-600 mt-0.5" />
                  <div>
                    <h4 className="font-medium text-purple-800 lowercase">increase posting frequency</h4>
                    <p className="text-sm text-purple-700">
                      Generate more content with Grok to reach your monthly posting targets
                    </p>
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Training Wizard */}
      <div className="fixed bottom-4 right-4 z-50">
        <OnboardingWizard />
      </div>

      <MasterFooter />
    </div>
  );
}