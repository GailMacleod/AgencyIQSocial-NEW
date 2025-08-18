import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/api";
import { TrendingUp, TrendingDown, Target, Users, MessageCircle, Eye, BarChart3, Calendar, Award } from "lucide-react";
import { format, startOfYear, endOfYear, eachMonthOfInterval, startOfMonth, endOfMonth } from "date-fns";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";
import { MetaPixelTracker } from "@/lib/meta-pixel";

interface MonthlyPerformance {
  month: string;
  posts: number;
  reach: number;
  engagement: number;
  conversions: number;
  targetPosts: number;
  targetReach: number;
  targetEngagement: number;
  targetConversions: number;
  performance: number;
}

interface YearlyAnalytics {
  yearToDate: {
    totalPosts: number;
    totalReach: number;
    avgEngagement: number;
    totalConversions: number;
    yearlyTargets: {
      posts: number;
      reach: number;
      engagement: number;
      conversions: number;
    };
  };
  monthly30DayCycles: MonthlyPerformance[];
  quarterlyTrends: {
    q1: { posts: number; reach: number; engagement: number; conversions: number };
    q2: { posts: number; reach: number; engagement: number; conversions: number };
    q3: { posts: number; reach: number; engagement: number; conversions: number };
    q4: { posts: number; reach: number; engagement: number; conversions: number };
  };
  bestPerformingMonth: MonthlyPerformance;
  brandPurposeAlignment: {
    growthGoal: { achieved: number; target: number; percentage: number };
    efficiencyGoal: { achieved: number; target: number; percentage: number };
    reachGoal: { achieved: number; target: number; percentage: number };
    engagementGoal: { achieved: number; target: number; percentage: number };
  };
  yearEndProjection: {
    posts: number;
    reach: number;
    engagement: number;
    conversions: number;
  };
}

export default function YearlyAnalytics() {
  const [currentYear] = useState(new Date().getFullYear());
  const [selectedQuarter, setSelectedQuarter] = useState<'q1' | 'q2' | 'q3' | 'q4'>('q2');

  const { data: yearlyAnalytics, isLoading } = useQuery<YearlyAnalytics>({
    queryKey: ["/api/yearly-analytics"],
    refetchInterval: 30000,
  });

  const { data: brandPurpose } = useQuery({
    queryKey: ["/api/brand-purpose"],
  });

  // Track yearly analytics page view and engagement
  useEffect(() => {
    if (yearlyAnalytics) {
      // Track comprehensive yearly analytics view
      MetaPixelTracker.trackAnalyticsView('yearly', yearlyAnalytics.monthlyPerformance?.map(() => 'comprehensive') || []);
      
      // Track advanced feature usage
      MetaPixelTracker.trackFeatureUsage('yearly_analytics_dashboard');
      
      // Track business performance insights
      const yearProgress = calculateYearProgress();
      const overallPerformance = yearlyAnalytics.yearEndProjection.conversions >= 1000 ? 'excellent' : 
                                yearlyAnalytics.yearEndProjection.conversions >= 500 ? 'good' : 'developing';
      
      MetaPixelTracker.trackCustomEvent('YearlyPerformanceReview', {
        year_progress: Math.round(yearProgress),
        overall_performance: overallPerformance,
        total_posts_ytd: yearlyAnalytics.monthlyPerformance?.reduce((sum, month) => sum + month.posts, 0) || 0,
        total_conversions_ytd: yearlyAnalytics.monthlyPerformance?.reduce((sum, month) => sum + month.conversions, 0) || 0,
        projected_year_end_conversions: yearlyAnalytics.yearEndProjection.conversions,
        best_performing_month: yearlyAnalytics.bestPerformingMonth?.month || 'none',
        quarterly_view: selectedQuarter
      });
      
      // Track goal achievement rates for business optimisation
      if (yearlyAnalytics.brandPurposeAlignment) {
        const avgGoalAchievement = (
          yearlyAnalytics.brandPurposeAlignment.growthGoal.percentage +
          yearlyAnalytics.brandPurposeAlignment.efficiencyGoal.percentage +
          yearlyAnalytics.brandPurposeAlignment.reachGoal.percentage +
          yearlyAnalytics.brandPurposeAlignment.engagementGoal.percentage
        ) / 4;
        
        MetaPixelTracker.trackCustomEvent('GoalAchievementAnalysis', {
          average_goal_achievement: Math.round(avgGoalAchievement),
          growth_goal_status: yearlyAnalytics.brandPurposeAlignment.growthGoal.percentage >= 90 ? 'achieved' : 'in_progress',
          efficiency_goal_status: yearlyAnalytics.brandPurposeAlignment.efficiencyGoal.percentage >= 90 ? 'achieved' : 'in_progress',
          reach_goal_status: yearlyAnalytics.brandPurposeAlignment.reachGoal.percentage >= 90 ? 'achieved' : 'in_progress',
          engagement_goal_status: yearlyAnalytics.brandPurposeAlignment.engagementGoal.percentage >= 90 ? 'achieved' : 'in_progress'
        });
      }
    }
  }, [yearlyAnalytics, selectedQuarter]);

  const getPerformanceColor = (percentage: number) => {
    if (percentage >= 90) return "text-green-600 bg-green-50 border-green-200";
    if (percentage >= 70) return "text-yellow-600 bg-yellow-50 border-yellow-200";
    return "text-red-600 bg-red-50 border-red-200";
  };

  const getPerformanceStatus = (percentage: number) => {
    if (percentage >= 100) return "Exceeded";
    if (percentage >= 90) return "On Track";
    if (percentage >= 70) return "Needs Attention";
    return "Critical";
  };

  const calculateYearProgress = () => {
    const now = new Date();
    const startYear = startOfYear(now);
    const endYear = endOfYear(now);
    const daysPassed = Math.floor((now.getTime() - startYear.getTime()) / (1000 * 60 * 60 * 24));
    const totalDays = Math.floor((endYear.getTime() - startYear.getTime()) / (1000 * 60 * 60 * 24));
    return (daysPassed / totalDays) * 100;
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <MasterHeader showBack="/analytics" title="Year-to-Date Analytics" />
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
      <MasterHeader showBack="/analytics" title="Year-to-Date Analytics" />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-heading font-light text-foreground lowercase mb-4">
            {currentYear} year-to-date performance
          </h1>
          <p className="text-gray-600 text-sm lowercase">
            comprehensive analysis in 30-day cycles measuring brand purpose goals
          </p>
          <div className="flex items-center justify-center space-x-4 mt-4">
            <div className="flex items-center space-x-2">
              <Calendar className="w-4 h-4 text-gray-500" />
              <span className="text-sm text-gray-600">
                {Math.round(calculateYearProgress())}% through {currentYear}
              </span>
            </div>
            <Progress value={calculateYearProgress()} className="w-32 h-2" />
          </div>
        </div>

        {/* Year-to-Date Summary Cards */}
        {yearlyAnalytics && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <Card className="relative overflow-hidden">
              <CardHeader className="pb-2">
                <div className="flex items-center space-x-2">
                  <BarChart3 className="w-5 h-5 text-purple-600" />
                  <span className="text-sm font-medium text-gray-600 lowercase">total posts</span>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-baseline">
                    <span className="text-3xl font-bold text-gray-900">
                      {yearlyAnalytics.yearToDate.totalPosts}
                    </span>
                    <span className="text-sm text-gray-500 ml-2">
                      / {yearlyAnalytics.yearToDate.yearlyTargets.posts}
                    </span>
                  </div>
                  <Progress 
                    value={(yearlyAnalytics.yearToDate.totalPosts / yearlyAnalytics.yearToDate.yearlyTargets.posts) * 100} 
                    className="h-2"
                  />
                  <Badge 
                    variant="outline" 
                    className={`text-xs lowercase ${getPerformanceColor((yearlyAnalytics.yearToDate.totalPosts / yearlyAnalytics.yearToDate.yearlyTargets.posts) * 100)}`}
                  >
                    {getPerformanceStatus((yearlyAnalytics.yearToDate.totalPosts / yearlyAnalytics.yearToDate.yearlyTargets.posts) * 100)}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            <Card className="relative overflow-hidden">
              <CardHeader className="pb-2">
                <div className="flex items-center space-x-2">
                  <Eye className="w-5 h-5 text-blue-600" />
                  <span className="text-sm font-medium text-gray-600 lowercase">total reach</span>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-baseline">
                    <span className="text-3xl font-bold text-gray-900">
                      {yearlyAnalytics.yearToDate.totalReach.toLocaleString()}
                    </span>
                    <span className="text-sm text-gray-500 ml-2">
                      / {yearlyAnalytics.yearToDate.yearlyTargets.reach.toLocaleString()}
                    </span>
                  </div>
                  <Progress 
                    value={(yearlyAnalytics.yearToDate.totalReach / yearlyAnalytics.yearToDate.yearlyTargets.reach) * 100} 
                    className="h-2"
                  />
                  <Badge 
                    variant="outline" 
                    className={`text-xs lowercase ${getPerformanceColor((yearlyAnalytics.yearToDate.totalReach / yearlyAnalytics.yearToDate.yearlyTargets.reach) * 100)}`}
                  >
                    {getPerformanceStatus((yearlyAnalytics.yearToDate.totalReach / yearlyAnalytics.yearToDate.yearlyTargets.reach) * 100)}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            <Card className="relative overflow-hidden">
              <CardHeader className="pb-2">
                <div className="flex items-center space-x-2">
                  <MessageCircle className="w-5 h-5 text-green-600" />
                  <span className="text-sm font-medium text-gray-600 lowercase">avg engagement</span>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-baseline">
                    <span className="text-3xl font-bold text-gray-900">
                      {yearlyAnalytics.yearToDate.avgEngagement.toFixed(1)}%
                    </span>
                    <span className="text-sm text-gray-500 ml-2">
                      / {yearlyAnalytics.yearToDate.yearlyTargets.engagement}%
                    </span>
                  </div>
                  <Progress 
                    value={(yearlyAnalytics.yearToDate.avgEngagement / yearlyAnalytics.yearToDate.yearlyTargets.engagement) * 100} 
                    className="h-2"
                  />
                  <Badge 
                    variant="outline" 
                    className={`text-xs lowercase ${getPerformanceColor((yearlyAnalytics.yearToDate.avgEngagement / yearlyAnalytics.yearToDate.yearlyTargets.engagement) * 100)}`}
                  >
                    {getPerformanceStatus((yearlyAnalytics.yearToDate.avgEngagement / yearlyAnalytics.yearToDate.yearlyTargets.engagement) * 100)}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            <Card className="relative overflow-hidden">
              <CardHeader className="pb-2">
                <div className="flex items-center space-x-2">
                  <Target className="w-5 h-5 text-orange-600" />
                  <span className="text-sm font-medium text-gray-600 lowercase">conversions</span>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-baseline">
                    <span className="text-3xl font-bold text-gray-900">
                      {yearlyAnalytics.yearToDate.totalConversions}
                    </span>
                    <span className="text-sm text-gray-500 ml-2">
                      / {yearlyAnalytics.yearToDate.yearlyTargets.conversions}
                    </span>
                  </div>
                  <Progress 
                    value={(yearlyAnalytics.yearToDate.totalConversions / yearlyAnalytics.yearToDate.yearlyTargets.conversions) * 100} 
                    className="h-2"
                  />
                  <Badge 
                    variant="outline" 
                    className={`text-xs lowercase ${getPerformanceColor((yearlyAnalytics.yearToDate.totalConversions / yearlyAnalytics.yearToDate.yearlyTargets.conversions) * 100)}`}
                  >
                    {getPerformanceStatus((yearlyAnalytics.yearToDate.totalConversions / yearlyAnalytics.yearToDate.yearlyTargets.conversions) * 100)}
                  </Badge>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Monthly 30-Day Cycles */}
        {yearlyAnalytics?.monthly30DayCycles && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="text-lg font-medium lowercase">monthly performance cycles</CardTitle>
              <p className="text-sm text-gray-600">30-day performance tracking aligned with brand purpose goals</p>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {yearlyAnalytics.monthly30DayCycles.map((month) => (
                  <div key={month.month} className="p-4 border rounded-lg hover:shadow-md transition-shadow">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="font-medium text-gray-900 lowercase">{month.month}</h3>
                      <Badge 
                        variant={month.performance >= 85 ? "default" : month.performance >= 70 ? "secondary" : "destructive"}
                        className="text-xs lowercase"
                      >
                        {month.performance}% performance
                      </Badge>
                    </div>
                    
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-600">posts:</span>
                        <span className="font-medium">{month.posts} / {month.targetPosts}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-600">reach:</span>
                        <span className="font-medium">{month.reach.toLocaleString()} / {month.targetReach.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-600">engagement:</span>
                        <span className="font-medium">{month.engagement}% / {month.targetEngagement}%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-600">conversions:</span>
                        <span className="font-medium">{month.conversions} / {month.targetConversions}</span>
                      </div>
                      
                      <Progress value={month.performance} className="h-2 mt-3" />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Best Performing Month Highlight */}
        {yearlyAnalytics?.bestPerformingMonth && (
          <Card className="mb-8 border-yellow-200 bg-yellow-50">
            <CardHeader>
              <div className="flex items-center space-x-2">
                <Award className="w-5 h-5 text-yellow-600" />
                <CardTitle className="text-lg font-medium lowercase text-yellow-800">
                  best performing month: {yearlyAnalytics.bestPerformingMonth.month}
                </CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-800">{yearlyAnalytics.bestPerformingMonth.posts}</div>
                  <div className="text-sm text-yellow-600">posts published</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-800">{yearlyAnalytics.bestPerformingMonth.reach.toLocaleString()}</div>
                  <div className="text-sm text-yellow-600">people reached</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-800">{yearlyAnalytics.bestPerformingMonth.engagement}%</div>
                  <div className="text-sm text-yellow-600">engagement rate</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-800">{yearlyAnalytics.bestPerformingMonth.conversions}</div>
                  <div className="text-sm text-yellow-600">conversions</div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Brand Purpose Alignment */}
        {yearlyAnalytics?.brandPurposeAlignment && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="text-lg font-medium lowercase">brand purpose goal alignment</CardTitle>
              <p className="text-sm text-gray-600">measuring progress against AI-defined objectives</p>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {Object.entries(yearlyAnalytics.brandPurposeAlignment).map(([key, goal]) => (
                  <div key={key} className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-medium text-gray-700 lowercase">{key.replace('Goal', '')} objective</span>
                      <Badge 
                        variant="outline"
                        className={`text-xs ${getPerformanceColor(goal.percentage)}`}
                      >
                        {goal.percentage}%
                      </Badge>
                    </div>
                    <Progress value={goal.percentage} className="h-3" />
                    <div className="flex justify-between text-xs text-gray-500">
                      <span>achieved: {goal.achieved}</span>
                      <span>target: {goal.target}</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Year-End Projection */}
        {yearlyAnalytics?.yearEndProjection && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="text-lg font-medium lowercase">year-end projection</CardTitle>
              <p className="text-sm text-gray-600">estimated performance based on current trends</p>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                <div className="text-center p-4 bg-purple-50 rounded-lg">
                  <div className="text-2xl font-bold text-purple-800">{yearlyAnalytics.yearEndProjection.posts}</div>
                  <div className="text-sm text-purple-600 lowercase">projected posts</div>
                </div>
                <div className="text-center p-4 bg-blue-50 rounded-lg">
                  <div className="text-2xl font-bold text-blue-800">{yearlyAnalytics.yearEndProjection.reach.toLocaleString()}</div>
                  <div className="text-sm text-blue-600 lowercase">projected reach</div>
                </div>
                <div className="text-center p-4 bg-green-50 rounded-lg">
                  <div className="text-2xl font-bold text-green-800">{yearlyAnalytics.yearEndProjection.engagement}%</div>
                  <div className="text-sm text-green-600 lowercase">projected engagement</div>
                </div>
                <div className="text-center p-4 bg-orange-50 rounded-lg">
                  <div className="text-2xl font-bold text-orange-800">{yearlyAnalytics.yearEndProjection.conversions}</div>
                  <div className="text-sm text-orange-600 lowercase">projected conversions</div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Action Items */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg font-medium lowercase">strategic recommendations</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-start space-x-3 p-3 bg-purple-50 border border-purple-200 rounded-lg">
                <Target className="w-5 h-5 text-purple-600 mt-0.5" />
                <div>
                  <h4 className="font-medium text-purple-800 lowercase">focus on consistency</h4>
                  <p className="text-sm text-purple-700">
                    Maintain steady posting frequency to achieve year-end targets
                  </p>
                </div>
              </div>
              <div className="flex items-start space-x-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                <Users className="w-5 h-5 text-blue-600 mt-0.5" />
                <div>
                  <h4 className="font-medium text-blue-800 lowercase">optimise reach strategies</h4>
                  <p className="text-sm text-blue-700">
                    Leverage Queensland-specific content during peak engagement periods
                  </p>
                </div>
              </div>
              <div className="flex items-start space-x-3 p-3 bg-green-50 border border-green-200 rounded-lg">
                <MessageCircle className="w-5 h-5 text-green-600 mt-0.5" />
                <div>
                  <h4 className="font-medium text-green-800 lowercase">enhance engagement</h4>
                  <p className="text-sm text-green-700">
                    Replicate successful strategies from your best performing month
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <MasterFooter />
    </div>
  );
}