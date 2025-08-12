import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Activity, BarChart3, Clock, User, Zap } from "lucide-react";

export default function AdminVideoPrompts() {
  const { data: promptData, isLoading, error } = useQuery({
    queryKey: ["/api/admin/video-prompts"],
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  if (isLoading) {
    return (
      <div className="p-6">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-64 mb-6"></div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-32 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <Card className="border-red-200">
          <CardContent className="p-6">
            <div className="text-center">
              <h3 className="text-lg font-semibold text-red-600 mb-2">Access Denied</h3>
              <p className="text-gray-600">Admin access required to view video prompt monitoring.</p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const { summary, prompts } = promptData || {};

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Video Prompts Monitoring</h1>
        <Badge variant="outline" className="text-green-600 border-green-200">
          <Activity className="w-4 h-4 mr-1" />
          Live Monitoring
        </Badge>
      </div>

      {/* Summary Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Prompts</CardTitle>
            <BarChart3 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{summary?.totalPrompts || 0}</div>
            <p className="text-xs text-muted-foreground">
              {summary?.last24Hours || 0} in last 24 hours
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Tokens</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{summary?.performance?.averageTokenUsage || 0}</div>
            <p className="text-xs text-muted-foreground">
              per generation
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Cache Hit Rate</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{summary?.performance?.averageCacheHitRate || '0%'}</div>
            <p className="text-xs text-muted-foreground">
              cost optimisation
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Platform Usage</CardTitle>
            <User className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {Object.entries(summary?.platformBreakdown || {}).map(([platform, count]) => (
                <div key={platform} className="flex justify-between text-sm">
                  <span className="capitalize">{platform}</span>
                  <span className="font-semibold">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Prompts */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Video Prompts</CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px]">
            <div className="space-y-4">
              {prompts?.map((prompt: any, index: number) => (
                <div key={`${prompt.timestamp}-${index}`} className="border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary">{prompt.platform}</Badge>
                      <Badge variant="outline">User {prompt.userId}</Badge>
                      {prompt.performance && (
                        <Badge variant="outline" className="text-xs">
                          {prompt.performance.totalTokens} tokens
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center text-sm text-muted-foreground">
                      <Clock className="w-4 h-4 mr-1" />
                      {new Date(prompt.timestamp).toLocaleString()}
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    <div>
                      <h4 className="font-semibold text-sm mb-1">Strategic Intent</h4>
                      <p className="text-sm text-gray-600">{prompt.strategicIntent || 'Default business growth'}</p>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold text-sm mb-1">Visual Theme</h4>
                      <p className="text-sm text-gray-600">{prompt.visualTheme || 'Professional business'}</p>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold text-sm mb-1">Original Prompt</h4>
                      <p className="text-sm bg-gray-50 p-2 rounded">{prompt.originalPrompt}</p>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold text-sm mb-1">Enhanced Cinematic Prompt</h4>
                      <p className="text-sm bg-blue-50 p-2 rounded">{prompt.enhancedPrompt}</p>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold text-sm mb-1">AI Generated Response</h4>
                      <p className="text-sm bg-green-50 p-2 rounded">{prompt.generatedResponse}</p>
                    </div>
                    
                    {prompt.performance && (
                      <div className="bg-gray-50 p-2 rounded">
                        <h4 className="font-semibold text-sm mb-1">Performance Metrics</h4>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                          <div>Cache: {prompt.performance.cacheTokens}</div>
                          <div>Total: {prompt.performance.totalTokens}</div>
                          <div>Prompt: {prompt.performance.promptTokens}</div>
                          <div>Hit Rate: {prompt.performance.cacheHitRate}</div>
                        </div>
                      </div>
                    )}
                  </div>
                  
                  {index < (prompts?.length - 1) && <Separator className="mt-4" />}
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}