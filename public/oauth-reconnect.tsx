import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { CheckCircle, XCircle, RefreshCw, ExternalLink } from 'lucide-react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { queryClient } from '@/lib/queryClient';

interface PlatformStatus {
  platform: string;
  connected: boolean;
  issue?: string;
  solution?: string;
  reconnectUrl?: string;
  permissions?: string[];
}

export default function OAuthReconnect() {
  const [reconnectingPlatforms, setReconnectingPlatforms] = useState(new Set<string>());

  const { data: connectionStatus, isLoading } = useQuery({
    queryKey: ['/api/oauth-status'],
    retry: false
  });

  const reconnectMutation = useMutation({
    mutationFn: async (platform: string) => {
      // Redirect to OAuth flow for the platform
      window.location.href = `/auth/${platform}`;
    },
    onMutate: (platform) => {
      setReconnectingPlatforms(prev => new Set(prev).add(platform));
    }
  });

  const testConnectionMutation = useMutation({
    mutationFn: async (platform: string) => {
      const response = await fetch('/api/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ platform })
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/oauth-status'] });
    }
  });

  const platformsConfig: PlatformStatus[] = [
    {
      platform: 'facebook',
      connected: false,
      issue: 'Invalid OAuth access token - Cannot parse access token',
      solution: 'Reconnect with pages_manage_posts and publish_actions permissions',
      reconnectUrl: '/auth/facebook/reconnect',
      permissions: ['pages_manage_posts', 'pages_read_engagement', 'publish_actions', 'email']
    },
    {
      platform: 'linkedin',
      connected: false,
      issue: 'Access token expired',
      solution: 'Reconnect LinkedIn account with w_member_social permission',
      reconnectUrl: '/auth/linkedin',
      permissions: ['r_liteprofile', 'r_emailaddress', 'w_member_social']
    },
    {
      platform: 'twitter',
      connected: false,
      issue: 'OAuth 1.0a incompatible with current posting API',
      solution: 'Upgrade to OAuth 2.0 with tweet.write permission',
      reconnectUrl: '/auth/twitter',
      permissions: ['tweet.read', 'tweet.write', 'users.read']
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Fix Your Social Media Connections
          </h1>
          <p className="text-lg text-gray-600">
            Your posts are ready to publish, but need fresh OAuth connections
          </p>
        </div>

        <Alert className="mb-6 border-red-200 bg-red-50">
          <XCircle className="h-4 w-4 text-red-600" />
          <AlertDescription className="text-red-800">
            <strong>CRITICAL:</strong> All 50 posts are failing due to expired OAuth tokens. 
            Reconnect each platform below to resume publishing.
          </AlertDescription>
        </Alert>

        <div className="grid gap-6 md:grid-cols-1 lg:grid-cols-2">
          {platformsConfig.map((platform) => (
            <Card key={platform.platform} className="border-2">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="capitalize text-xl">
                    {platform.platform === 'twitter' ? 'X (Twitter)' : platform.platform}
                  </CardTitle>
                  <Badge variant={platform.connected ? "default" : "destructive"}>
                    {platform.connected ? (
                      <><CheckCircle className="w-3 h-3 mr-1" /> Connected</>
                    ) : (
                      <><XCircle className="w-3 h-3 mr-1" /> Disconnected</>
                    )}
                  </Badge>
                </div>
                <CardDescription>
                  {platform.issue}
                </CardDescription>
              </CardHeader>
              
              <CardContent className="space-y-4">
                <div className="bg-yellow-50 p-3 rounded-lg border border-yellow-200">
                  <p className="text-sm text-yellow-800 font-medium">Solution:</p>
                  <p className="text-sm text-yellow-700">{platform.solution}</p>
                </div>

                <div className="space-y-2">
                  <p className="text-sm font-medium text-gray-700">Required Permissions:</p>
                  <div className="flex flex-wrap gap-1">
                    {platform.permissions?.map((permission) => (
                      <Badge key={permission} variant="outline" className="text-xs">
                        {permission}
                      </Badge>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button
                    onClick={() => reconnectMutation.mutate(platform.platform)}
                    disabled={reconnectingPlatforms.has(platform.platform)}
                    className="flex-1"
                  >
                    {reconnectingPlatforms.has(platform.platform) ? (
                      <><RefreshCw className="w-4 h-4 mr-2 animate-spin" /> Reconnecting...</>
                    ) : (
                      <><ExternalLink className="w-4 h-4 mr-2" /> Reconnect {platform.platform}</>
                    )}
                  </Button>
                  
                  <Button
                    variant="outline"
                    onClick={() => testConnectionMutation.mutate(platform.platform)}
                    disabled={testConnectionMutation.isPending}
                  >
                    Test
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <Card className="mt-6 bg-blue-50 border-blue-200">
          <CardHeader>
            <CardTitle className="text-blue-900">Next Steps</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-blue-800">
            <div className="flex items-start gap-2">
              <span className="bg-blue-600 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs font-bold mt-0.5">1</span>
              <p>Click "Reconnect" for each platform above</p>
            </div>
            <div className="flex items-start gap-2">
              <span className="bg-blue-600 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs font-bold mt-0.5">2</span>
              <p>Grant ALL requested permissions during OAuth flow</p>
            </div>
            <div className="flex items-start gap-2">
              <span className="bg-blue-600 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs font-bold mt-0.5">3</span>
              <p>For Facebook: Select your business pages when prompted</p>
            </div>
            <div className="flex items-start gap-2">
              <span className="bg-blue-600 text-white rounded-full w-5 h-5 flex items-center justify-center text-xs font-bold mt-0.5">4</span>
              <p>Return here and test connections before publishing</p>
            </div>
          </CardContent>
        </Card>

        <div className="mt-6 text-center">
          <Button
            onClick={() => window.location.href = '/dashboard'}
            variant="outline"
            size="lg"
          >
            Return to Dashboard
          </Button>
        </div>
      </div>
    </div>
  );
}