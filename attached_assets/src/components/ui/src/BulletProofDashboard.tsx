import { useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import MasterHeader from '@/components/master-header';
import MasterFooter from '@/components/master-footer';
import { CheckCircle, XCircle, AlertTriangle, Shield, RefreshCw, Activity } from 'lucide-react';
import { apiRequest } from '@/lib/queryClient';

interface BulletproofTestResult {
  overall: {
    passed: boolean;
    score: number;
    reliability: string;
  };
  platforms: {
    [platform: string]: {
      connected: boolean;
      healthy: boolean;
      publishTest: boolean;
      fallbackReady: boolean;
      score: number;
    };
  };
  systemHealth: {
    tokenValidation: boolean;
    connectionStability: boolean;
    fallbackSystems: boolean;
    errorRecovery: boolean;
  };
  recommendations: string[];
  timestamp?: string;
}

export default function BulletproofDashboard() {
  const [isRunningTest, setIsRunningTest] = useState(false);
  const [lastTestResult, setLastTestResult] = useState<BulletproofTestResult | null>(null);

  // Platform health monitoring
  const { data: platformHealth, isLoading: healthLoading, refetch: refetchHealth } = useQuery({
    queryKey: ['/api/platform-health'],
  });

  // Run bulletproof system test
  const bulletproofTestMutation = useMutation({
    mutationFn: async () => {
      const result = await apiRequest('/api/bulletproof-test');
      return result;
    },
    onSuccess: (data) => {
      setLastTestResult(data);
      setIsRunningTest(false);
    },
    onError: (error) => {
      console.error('Bulletproof test failed:', error);
      setIsRunningTest(false);
    }
  });

  // Repair connections
  const repairConnectionsMutation = useMutation({
    mutationFn: async (platform?: string) => {
      return await apiRequest('/api/repair-connections', 'POST', { platform });
    },
    onSuccess: () => {
      refetchHealth();
    }
  });

  const runBulletproofTest = () => {
    setIsRunningTest(true);
    bulletproofTestMutation.mutate();
  };

  const getReliabilityColor = (score: number) => {
    if (score >= 99) return 'bg-green-500';
    if (score >= 95) return 'bg-blue-500';
    if (score >= 85) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  const getStatusIcon = (status: boolean) => {
    return status ? (
      <CheckCircle className="h-5 w-5 text-green-500" />
    ) : (
      <XCircle className="h-5 w-5 text-red-500" />
    );
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <MasterHeader title="Bulletproof Publishing Dashboard" />
      
      <div className="container mx-auto px-4 py-8 max-w-6xl">
        
        {/* Overall System Status */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-blue-500" />
                System Reliability
              </CardTitle>
            </CardHeader>
            <CardContent>
              {lastTestResult ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-2xl font-bold">{lastTestResult.overall.score}%</span>
                    <Badge variant={lastTestResult.overall.passed ? "default" : "destructive"}>
                      {lastTestResult.overall.reliability}
                    </Badge>
                  </div>
                  <Progress 
                    value={lastTestResult.overall.score} 
                    className="h-3"
                  />
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Last tested: {lastTestResult.timestamp ? 
                      new Date(lastTestResult.timestamp).toLocaleString() : 'Recently'}
                  </p>
                </div>
              ) : (
                <div className="text-center py-4">
                  <p className="text-gray-500 mb-3">No test results available</p>
                  <Button 
                    onClick={runBulletproofTest} 
                    disabled={isRunningTest}
                    size="sm"
                  >
                    {isRunningTest ? (
                      <>
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                        Testing...
                      </>
                    ) : (
                      'Run Test'
                    )}
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-green-500" />
                Platform Health
              </CardTitle>
            </CardHeader>
            <CardContent>
              {platformHealth ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-2xl font-bold">
                      {platformHealth.overallHealth?.healthy || 0}/{platformHealth.overallHealth?.total || 0}
                    </span>
                    <Badge variant="secondary">Healthy</Badge>
                  </div>
                  <Progress 
                    value={platformHealth.overallHealth?.total > 0 ? 
                      (platformHealth.overallHealth.healthy / platformHealth.overallHealth.total) * 100 : 0} 
                    className="h-3"
                  />
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Active platform connections
                  </p>
                </div>
              ) : (
                <div className="flex items-center justify-center h-16">
                  <RefreshCw className="h-5 w-5 animate-spin text-gray-400" />
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle>Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button 
                onClick={runBulletproofTest} 
                disabled={isRunningTest}
                className="w-full"
                size="sm"
              >
                {isRunningTest ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Running Test...
                  </>
                ) : (
                  <>
                    <Shield className="h-4 w-4 mr-2" />
                    Run Full Test
                  </>
                )}
              </Button>
              
              <Button 
                onClick={() => repairConnectionsMutation.mutate()}
                disabled={repairConnectionsMutation.isPending}
                variant="outline"
                className="w-full"
                size="sm"
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Repair All
              </Button>
              
              <Button 
                onClick={() => refetchHealth()}
                variant="ghost"
                className="w-full"
                size="sm"
              >
                <Activity className="h-4 w-4 mr-2" />
                Refresh Status
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Platform Status Details */}
        {(platformHealth?.platforms || lastTestResult?.platforms) && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Platform Connection Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(lastTestResult?.platforms || {}).map(([platform, status]) => (
                  <div key={platform} className="border rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-medium capitalize">{platform}</h3>
                      <Badge 
                        variant={status.healthy ? "default" : "destructive"}
                        className="text-xs"
                      >
                        {status.score}%
                      </Badge>
                    </div>
                    
                    <div className="space-y-2 text-sm">
                      <div className="flex items-center justify-between">
                        <span>Connected</span>
                        {getStatusIcon(status.connected)}
                      </div>
                      <div className="flex items-center justify-between">
                        <span>Healthy</span>
                        {getStatusIcon(status.healthy)}
                      </div>
                      <div className="flex items-center justify-between">
                        <span>Publish Test</span>
                        {getStatusIcon(status.publishTest)}
                      </div>
                      <div className="flex items-center justify-between">
                        <span>Fallback Ready</span>
                        {getStatusIcon(status.fallbackReady)}
                      </div>
                    </div>
                    
                    {!status.healthy && (
                      <Button 
                        onClick={() => repairConnectionsMutation.mutate(platform)}
                        disabled={repairConnectionsMutation.isPending}
                        size="sm"
                        variant="outline"
                        className="w-full"
                      >
                        Repair
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* System Health Indicators */}
        {lastTestResult?.systemHealth && (
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>System Health Indicators</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-4 border rounded-lg">
                  {getStatusIcon(lastTestResult.systemHealth.tokenValidation)}
                  <p className="mt-2 text-sm font-medium">Token Validation</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  {getStatusIcon(lastTestResult.systemHealth.connectionStability)}
                  <p className="mt-2 text-sm font-medium">Connection Stability</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  {getStatusIcon(lastTestResult.systemHealth.fallbackSystems)}
                  <p className="mt-2 text-sm font-medium">Fallback Systems</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  {getStatusIcon(lastTestResult.systemHealth.errorRecovery)}
                  <p className="mt-2 text-sm font-medium">Error Recovery</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Recommendations */}
        {lastTestResult?.recommendations && lastTestResult.recommendations.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
                System Recommendations
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {lastTestResult.recommendations.map((recommendation, index) => (
                  <Alert key={index}>
                    <AlertDescription>{recommendation}</AlertDescription>
                  </Alert>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Help Section */}
        <Card className="mt-8">
          <CardHeader>
            <CardTitle>About Bulletproof Publishing</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="prose prose-sm max-w-none dark:prose-invert">
              <p>
                The Bulletproof Publishing System ensures 99.9% reliability for your social media posts 
                across all connected platforms. It includes:
              </p>
              <ul>
                <li><strong>Real-time Health Monitoring:</strong> Continuous validation of platform connections</li>
                <li><strong>Automatic Token Refresh:</strong> Prevents expired token failures</li>
                <li><strong>Fallback Systems:</strong> Alternative publishing methods when primary fails</li>
                <li><strong>Error Recovery:</strong> Automatic repair of connection issues</li>
                <li><strong>Comprehensive Testing:</strong> Regular validation of all system components</li>
              </ul>
              <p>
                Run regular tests to maintain optimal system performance and address any issues before 
                they affect your posting schedule.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      <MasterFooter />
    </div>
  );
}