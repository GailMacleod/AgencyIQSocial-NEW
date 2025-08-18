import { useQuery } from "@tanstack/react-query";
import { QuickActionsPanel } from "./QuickActionsPanel";
import { PlatformStatusWidget } from "./PlatformStatusWidget";
import { ContextualTooltip } from "./ContextualTooltip";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TrendingUp, Users, Calendar, Zap } from "lucide-react";

export function EnhancedDashboard() {
  const { data: usage } = useQuery({
    queryKey: ['/api/subscription-usage'],
    enabled: true
  });

  const { data: posts } = useQuery({
    queryKey: ['/api/posts'],
    enabled: true
  });

  const recentPosts = (posts as any)?.slice(0, 5) || [];
  const publishedPosts = (posts as any)?.filter((p: any) => p.status === 'published') || [];

  return (
    <div className="space-y-6">
      {/* Quick Actions Panel */}
      <QuickActionsPanel 
        remainingPosts={usage?.remainingPosts} 
        totalPosts={usage?.totalAllocation} 
      />

      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Platform Status */}
        <div className="lg:col-span-1">
          <PlatformStatusWidget />
        </div>

        {/* Subscription Overview */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium flex items-center space-x-2">
              <Zap className="w-4 h-4 text-yellow-500" />
              <span>Subscription Overview</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Plan</span>
                <Badge variant="outline" className="capitalize">
                  {usage?.subscriptionPlan || 'Basic'}
                </Badge>
              </div>
              <div className="flex justify-between items-center">
                <ContextualTooltip 
                  term="Posts Used" 
                  explanation="Only published posts count toward your quota"
                />
                <span className="font-medium">
                  {usage?.usedPosts || 0} / {usage?.totalAllocation || 30}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Usage</span>
                <span className="font-medium">{usage?.usagePercentage || 0}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div 
                  className="bg-purple-600 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${usage?.usagePercentage || 0}%` }}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Analytics Overview */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium flex items-center space-x-2">
              <TrendingUp className="w-4 h-4 text-green-500" />
              <span>Performance</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Published Posts</span>
                <span className="font-medium">{publishedPosts.length}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Avg. Engagement</span>
                <span className="font-medium text-green-600">+12%</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Best Platform</span>
                <Badge variant="outline" className="bg-blue-50 text-blue-700">
                  LinkedIn
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Activity */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium flex items-center space-x-2">
            <Calendar className="w-4 h-4 text-blue-500" />
            <span>Recent Activity</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {recentPosts.length > 0 ? (
              recentPosts.map((post: any) => (
                <div key={post.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-2 h-2 rounded-full bg-purple-500"></div>
                    <div>
                      <p className="text-sm font-medium">{post.platform}</p>
                      <p className="text-xs text-gray-600 truncate max-w-[300px]">
                        {post.content}
                      </p>
                    </div>
                  </div>
                  <Badge variant="outline" className="text-xs">
                    {post.status}
                  </Badge>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Users className="w-8 h-8 mx-auto mb-2 text-gray-300" />
                <p className="text-sm">No recent activity</p>
                <p className="text-xs">Generate your first content to get started</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}