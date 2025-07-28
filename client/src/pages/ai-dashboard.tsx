import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from "@/lib/queryClient";
import { 
  Brain, 
  TrendingUp, 
  Target, 
  Search, 
  Clock, 
  BarChart3, 
  Users, 
  Award,
  Sparkles,
  Zap,
  ArrowUp,
  ArrowDown
} from 'lucide-react';

interface OptimizedContent {
  content: string;
  hashtags: string[];
  keywords: string[];
  metaTags: string[];
  optimalTiming: string;
  engagementScore: number;
  cta: string;
}

interface LearningInsights {
  insights: string[];
  recommendations: string[];
  projectedImprovement: number;
}

interface GrowthMetrics {
  reachGrowth: number;
  engagementGrowth: number;
  conversionRate: number;
  brandAwareness: number;
  customerAcquisition: number;
  retentionRate: number;
}

export default function AIDashboard() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedContentType, setSelectedContentType] = useState<'awareness' | 'engagement' | 'sales' | 'retention'>('engagement');
  const [selectedPlatform, setSelectedPlatform] = useState('facebook');

  // Fetch learning insights
  const { data: learningData, isLoading: learningLoading } = useQuery({
    queryKey: ['/api/ai/learning-insights/2'],
    refetchInterval: 300000 // 5 minutes
  });

  // Fetch growth insights
  const { data: growthData, isLoading: growthLoading } = useQuery({
    queryKey: ['/api/analytics/growth-insights'],
    refetchInterval: 60000 // 1 minute
  });

  // Fetch audience insights
  const { data: audienceData, isLoading: audienceLoading } = useQuery({
    queryKey: ['/api/analytics/audience-insights'],
    refetchInterval: 300000 // 5 minutes
  });

  // Content optimisation mutation
  const optimiseContentMutation = useMutation({
    mutationFn: async ({ contentType, platform }: { contentType: string; platform: string }) => {
      const response = await apiRequest('POST', '/api/ai/optimise-content', {
        contentType,
        platform
      });
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Content Optimised",
        description: "AI has generated optimised content for maximum engagement",
        variant: "default",
        duration: 4000
      });
    },
    onError: (error) => {
      toast({
        title: "Optimisation Failed",
        description: "Failed to optimise content. Please try again.",
        variant: "destructive",
        duration: 4000
      });
    }
  });

  // SEO generation mutation
  const generateSEOMutation = useMutation({
    mutationFn: async ({ content, industry, location }: { content: string; industry: string; location: string }) => {
      const response = await apiRequest('POST', '/api/ai/generate-seo', {
        content,
        industry,
        location
      });
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "SEO Generated",
        description: "Keywords, hashtags, and meta tags optimised for Queensland market",
        variant: "default",
        duration: 4000
      });
    }
  });

  const handleOptimiseContent = () => {
    optimiseContentMutation.mutate({
      contentType: selectedContentType,
      platform: selectedPlatform
    });
  };

  const handleGenerateSEO = () => {
    generateSEOMutation.mutate({
      content: "Sample Queensland small business content",
      industry: "professional-services",
      location: "Queensland"
    });
  };

  const renderGrowthMetric = (label: string, value: number, isPercentage: boolean = true) => {
    const isPositive = value > 0;
    const displayValue = isPercentage ? `${value.toFixed(1)}%` : value.toString();
    
    return (
      <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
        <span className="text-sm font-medium">{label}</span>
        <div className="flex items-center gap-1">
          {isPositive ? (
            <ArrowUp className="w-4 h-4 text-green-500" />
          ) : (
            <ArrowDown className="w-4 h-4 text-red-500" />
          )}
          <span className={`font-bold ${isPositive ? 'text-green-600' : 'text-red-600'}`}>
            {displayValue}
          </span>
        </div>
      </div>
    );
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <Brain className="w-8 h-8 text-blue-600" />
        <div>
          <h1 className="text-3xl font-bold">AI Content & Analytics Dashboard</h1>
          <p className="text-gray-600">World-class AI optimisation for Queensland small businesses</p>
        </div>
      </div>

      <Tabs defaultValue="optimise" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="optimise" className="flex items-center gap-2">
            <Sparkles className="w-4 h-4" />
            Content AI
          </TabsTrigger>
          <TabsTrigger value="learning" className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4" />
            Learning
          </TabsTrigger>
          <TabsTrigger value="analytics" className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4" />
            Growth Analytics
          </TabsTrigger>
          <TabsTrigger value="audience" className="flex items-center gap-2">
            <Users className="w-4 h-4" />
            Audience
          </TabsTrigger>
        </TabsList>

        <TabsContent value="optimise" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-500" />
                  AI Content Optimisation
                </CardTitle>
                <CardDescription>
                  Generate personalized content templates for high engagement and sales CTAs
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Content Type</label>
                  <div className="grid grid-cols-2 gap-2">
                    {(['awareness', 'engagement', 'sales', 'retention'] as const).map((type) => (
                      <Button
                        key={type}
                        variant={selectedContentType === type ? 'default' : 'outline'}
                        size="sm"
                        onClick={() => setSelectedContentType(type)}
                        className="capitalize"
                      >
                        {type}
                      </Button>
                    ))}
                  </div>
                </div>
                
                <div>
                  <label className="text-sm font-medium mb-2 block">Platform</label>
                  <div className="grid grid-cols-3 gap-2">
                    {['facebook', 'instagram', 'linkedin'].map((platform) => (
                      <Button
                        key={platform}
                        variant={selectedPlatform === platform ? 'default' : 'outline'}
                        size="sm"
                        onClick={() => setSelectedPlatform(platform)}
                        className="capitalize"
                      >
                        {platform}
                      </Button>
                    ))}
                  </div>
                </div>

                <Button 
                  onClick={handleOptimiseContent}
                  disabled={optimiseContentMutation.isPending}
                  className="w-full"
                >
                  {optimiseContentMutation.isPending ? 'Optimising...' : 'Generate Optimised Content'}
                </Button>

                {optimiseContentMutation.data && (
                  <div className="mt-4 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <h4 className="font-semibold text-blue-800 dark:text-blue-200 mb-2">Optimised Content</h4>
                    <p className="text-sm mb-3">{optimiseContentMutation.data.content?.content}</p>
                    <div className="flex flex-wrap gap-1 mb-2">
                      {optimiseContentMutation.data.content?.hashtags?.slice(0, 5).map((tag: string, i: number) => (
                        <Badge key={i} variant="secondary" className="text-xs">{tag}</Badge>
                      ))}
                    </div>
                    <div className="flex items-center justify-between text-xs text-blue-600 dark:text-blue-300">
                      <span>Engagement Score: {optimiseContentMutation.data.content?.engagementScore}%</span>
                      <span>Optimal Time: {optimiseContentMutation.data.content?.optimalTiming}</span>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="w-5 h-5 text-green-500" />
                  SEO Optimisation
                </CardTitle>
                <CardDescription>
                  Generate keywords, hashtags, and meta tags for Queensland market
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="text-sm text-gray-600 dark:text-gray-400">
                  AI-powered SEO optimisation specifically designed for Queensland small businesses, 
                  including local keywords, trending hashtags, and meta tags for maximum visibility.
                </div>

                <Button 
                  onClick={handleGenerateSEO}
                  disabled={generateSEOMutation.isPending}
                  className="w-full"
                >
                  {generateSEOMutation.isPending ? 'Generating...' : 'Generate SEO Package'}
                </Button>

                {generateSEOMutation.data && (
                  <div className="mt-4 space-y-3">
                    <div className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                      <h5 className="font-medium text-green-800 dark:text-green-200 mb-2">Keywords</h5>
                      <div className="flex flex-wrap gap-1">
                        {generateSEOMutation.data.seo?.keywords?.map((keyword: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs">{keyword}</Badge>
                        ))}
                      </div>
                    </div>
                    
                    <div className="p-3 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                      <h5 className="font-medium text-purple-800 dark:text-purple-200 mb-2">Hashtags</h5>
                      <div className="flex flex-wrap gap-1">
                        {generateSEOMutation.data.seo?.hashtags?.slice(0, 10).map((tag: string, i: number) => (
                          <Badge key={i} variant="secondary" className="text-xs">{tag}</Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="learning" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Brain className="w-5 h-5 text-purple-500" />
                AI Learning & 30-Day Optimization Cycles
              </CardTitle>
              <CardDescription>
                Machine learning algorithm improving post reach and conversion strategies
              </CardDescription>
            </CardHeader>
            <CardContent>
              {learningLoading ? (
                <div className="text-center py-8">
                  <div className="animate-spin w-8 h-8 border-4 border-primary border-t-transparent rounded-full mx-auto" />
                  <p className="mt-2 text-sm text-gray-600">Analyzing performance data...</p>
                </div>
              ) : (learningData as LearningInsights)?.insights ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-semibold">Projected Improvement</h4>
                    <div className="flex items-center gap-2">
                      <Progress value={(learningData as LearningInsights).insights.projectedImprovement} className="w-24" />
                      <span className="font-bold text-green-600">
                        +{(learningData as LearningInsights).insights.projectedImprovement}%
                      </span>
                    </div>
                  </div>

                  <div>
                    <h5 className="font-medium mb-3">AI Insights</h5>
                    <div className="space-y-2">
                      {(learningData as LearningInsights).insights.insights?.map((insight: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 p-2 bg-blue-50 dark:bg-blue-900/20 rounded">
                          <Target className="w-4 h-4 text-blue-500 mt-0.5 flex-shrink-0" />
                          <span className="text-sm">{insight}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h5 className="font-medium mb-3">Recommendations</h5>
                    <div className="space-y-2">
                      {(learningData as LearningInsights).insights.recommendations?.map((rec: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 p-2 bg-green-50 dark:bg-green-900/20 rounded">
                          <Award className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                          <span className="text-sm">{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Brain className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>Insufficient data for learning analysis</p>
                  <p className="text-sm">Publish more content to unlock AI insights</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {growthLoading ? (
              <div className="col-span-full text-center py-8">
                <div className="animate-spin w-8 h-8 border-4 border-primary border-t-transparent rounded-full mx-auto" />
                <p className="mt-2 text-sm text-gray-600">Loading growth analytics...</p>
              </div>
            ) : growthData?.insights ? (
              <>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Reach Growth</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {renderGrowthMetric('Current Period', growthData.insights.currentPeriod?.reachGrowth || 0, false)}
                    {renderGrowthMetric('Growth Rate', growthData.insights.growth?.reachGrowth || 0)}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Engagement</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {renderGrowthMetric('Current Period', growthData.insights.currentPeriod?.engagementGrowth || 0, false)}
                    {renderGrowthMetric('Growth Rate', growthData.insights.growth?.engagementGrowth || 0)}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-lg">Conversions</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {renderGrowthMetric('Conversion Rate', growthData.insights.currentPeriod?.conversionRate || 0)}
                    {renderGrowthMetric('Growth Rate', growthData.insights.growth?.conversionRate || 0)}
                  </CardContent>
                </Card>

                <Card className="md:col-span-2 lg:col-span-3">
                  <CardHeader>
                    <CardTitle>AI Recommendations</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {growthData.insights.recommendations?.map((rec: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                          <Sparkles className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" />
                          <span className="text-sm">{rec}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </>
            ) : (
              <div className="col-span-full text-center py-8 text-gray-500">
                <BarChart3 className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No analytics data available</p>
                <p className="text-sm">Publish content to start tracking growth metrics</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="audience" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {audienceLoading ? (
              <div className="col-span-full text-center py-8">
                <div className="animate-spin w-8 h-8 border-4 border-primary border-t-transparent rounded-full mx-auto" />
                <p className="mt-2 text-sm text-gray-600">Analyzing audience data...</p>
              </div>
            ) : audienceData?.insights ? (
              <>
                <Card>
                  <CardHeader>
                    <CardTitle>Demographics</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {Object.entries(audienceData.insights.demographics || {}).map(([age, percentage]) => (
                        <div key={age} className="flex items-center justify-between">
                          <span className="text-sm">{age} years</span>
                          <div className="flex items-center gap-2">
                            <Progress value={percentage as number} className="w-16" />
                            <span className="text-sm font-medium w-8">{percentage}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Geographic Reach</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {Object.entries(audienceData.insights.geographicReach || {}).map(([location, percentage]) => (
                        <div key={location} className="flex items-center justify-between">
                          <span className="text-sm">{location}</span>
                          <div className="flex items-center gap-2">
                            <Progress value={percentage as number} className="w-16" />
                            <span className="text-sm font-medium w-8">{percentage}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Top Interests</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-2">
                      {audienceData.insights.interests?.map((interest: string, i: number) => (
                        <Badge key={i} variant="outline">{interest}</Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>Optimal Content Types</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {audienceData.insights.optimalContentTypes?.map((type: string, i: number) => (
                        <div key={i} className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800 rounded">
                          <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                          <span className="text-sm">{type}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </>
            ) : (
              <div className="col-span-full text-center py-8 text-gray-500">
                <Users className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No audience data available</p>
                <p className="text-sm">Audience insights will appear as engagement grows</p>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}