import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { CheckCircle, XCircle, AlertTriangle, Zap, Clock, Shield, RefreshCw } from 'lucide-react';
import { apiRequest } from '@/lib/queryClient';

interface AutoPostingResult {
  success: boolean;
  postsProcessed: number;
  postsPublished: number;
  postsFailed: number;
  connectionRepairs: string[];
  errors: string[];
  message: string;
}

export default function AutoPostingEnforcer() {
  const [lastResult, setLastResult] = useState<AutoPostingResult | null>(null);
  const queryClient = useQueryClient();

  const enforceAutoPostingMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest('POST', '/api/enforce-auto-posting', {});
    },
    onSuccess: (result: AutoPostingResult) => {
      setLastResult(result);
      // Refresh relevant queries
      queryClient.invalidateQueries({ queryKey: ['/api/posts'] });
      queryClient.invalidateQueries({ queryKey: ['/api/subscription-usage'] });
      queryClient.invalidateQueries({ queryKey: ['/api/platform-health'] });
    },
    onError: (error) => {
      console.error('Auto-posting enforcement failed:', error);
      setLastResult({
        success: false,
        postsProcessed: 0,
        postsPublished: 0,
        postsFailed: 0,
        connectionRepairs: [],
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        message: 'Auto-posting enforcement failed'
      });
    }
  });

  const reconnectFacebookMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest('GET', '/api/reconnect/facebook', {});
      return response.json();
    },
    onSuccess: (data) => {
      if (data.success && data.authUrl) {
        window.open(data.authUrl, '_blank', 'width=600,height=700');
      }
    },
    onError: (error) => {
      console.error('Facebook reconnection error:', error);
    }
  });

  const triggerAutoPosting = () => {
    enforceAutoPostingMutation.mutate();
  };

  const handleFacebookReconnect = () => {
    reconnectFacebookMutation.mutate();
  };

  const getStatusColor = (success: boolean) => {
    return success ? 'text-green-600' : 'text-red-600';
  };

  const getStatusIcon = (success: boolean) => {
    return success ? CheckCircle : XCircle;
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Shield className="w-5 h-5 text-blue-600" />
          <span>Impatient?</span>
        </CardTitle>
        <p className="text-sm text-gray-600">
          This action over rides the calendar Schedule for a power burst
        </p>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Trigger Button */}
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-medium text-gray-900">Enforce Auto-Publishing</h3>
            <p className="text-sm text-gray-500">
              Process all pending posts
            </p>
          </div>
          <Button
            onClick={triggerAutoPosting}
            disabled={enforceAutoPostingMutation.isPending}
            className="bg-blue-600 hover:bg-blue-700 text-white"
          >
            {enforceAutoPostingMutation.isPending ? (
              <>
                <Clock className="w-4 h-4 mr-2 animate-spin" />
                Processing...
              </>
            ) : (
              <>
                <Zap className="w-4 h-4 mr-2" />
                Enforce Publishing
              </>
            )}
          </Button>
        </div>

        {/* Progress Indicator */}
        {enforceAutoPostingMutation.isPending && (
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Processing posts...</span>
              <span>Please wait</span>
            </div>
            <Progress value={undefined} className="w-full animate-pulse" />
          </div>
        )}

        {/* Results Display */}
        {lastResult && (
          <div className="space-y-4 border-t pt-4">
            <div className="flex items-center justify-between">
              <h4 className="font-medium text-gray-900">Last Enforcement Results</h4>
              <Badge variant={lastResult.success ? "default" : "destructive"}>
                {lastResult.success ? "Success" : "Issues Found"}
              </Badge>
            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center p-3 bg-blue-50 rounded-lg">
                <div className="text-2xl font-bold text-blue-600">
                  {lastResult.postsProcessed}
                </div>
                <div className="text-sm text-blue-600">Posts Processed</div>
              </div>
              
              <div className="text-center p-3 bg-green-50 rounded-lg">
                <div className="text-2xl font-bold text-green-600">
                  {lastResult.postsPublished}
                </div>
                <div className="text-sm text-green-600">Successfully Published</div>
              </div>
              
              <div className="text-center p-3 bg-red-50 rounded-lg">
                <div className="text-2xl font-bold text-red-600">
                  {lastResult.postsFailed}
                </div>
                <div className="text-sm text-red-600">Failed</div>
              </div>
            </div>

            {/* Success Rate */}
            {lastResult.postsProcessed > 0 && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Success Rate</span>
                  <span>
                    {Math.round((lastResult.postsPublished / lastResult.postsProcessed) * 100)}%
                  </span>
                </div>
                <Progress 
                  value={(lastResult.postsPublished / lastResult.postsProcessed) * 100} 
                  className="w-full"
                />
              </div>
            )}

            {/* Connection Repairs */}
            {lastResult.connectionRepairs.length > 0 && (
              <div className="space-y-2">
                <h5 className="font-medium text-gray-900 flex items-center">
                  <CheckCircle className="w-4 h-4 mr-2 text-green-600" />
                  Connection Repairs
                </h5>
                <div className="space-y-1">
                  {lastResult.connectionRepairs.map((repair, index) => (
                    <div key={index} className="text-sm text-green-600 bg-green-50 p-2 rounded">
                      {repair}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Errors */}
            {lastResult.errors.length > 0 && (
              <div className="space-y-2">
                <h5 className="font-medium text-gray-900 flex items-center">
                  <AlertTriangle className="w-4 h-4 mr-2 text-red-600" />
                  Issues Found
                </h5>
                <div className="space-y-1">
                  {lastResult.errors.map((error, index) => (
                    <Alert key={index} variant="destructive">
                      <AlertDescription className="text-sm">
                        {error}
                        {error.includes('Missing permissions') && (
                          <div className="mt-2">
                            <Button 
                              onClick={handleFacebookReconnect}
                              disabled={reconnectFacebookMutation.isPending}
                              variant="outline"
                              size="sm"
                              className="text-blue-600 border-blue-200 hover:bg-blue-50"
                            >
                              <RefreshCw className={`w-3 h-3 mr-1 ${reconnectFacebookMutation.isPending ? 'animate-spin' : ''}`} />
                              Fix Facebook Permissions
                            </Button>
                          </div>
                        )}
                      </AlertDescription>
                    </Alert>
                  ))}
                </div>
              </div>
            )}

            {/* Message */}
            <Alert variant={lastResult.success ? "default" : "destructive"}>
              <AlertDescription>
                {lastResult.message}
              </AlertDescription>
            </Alert>
          </div>
        )}

        {/* Instructions */}
        <div className="bg-blue-50 p-4 rounded-lg">
          <h5 className="font-medium text-blue-900 mb-2">How It Works</h5>
          <ul className="text-sm text-blue-800 space-y-1">
            <li>• All approved posts are sent to publication</li>
            <li>• Over rides you calendar schedule</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}