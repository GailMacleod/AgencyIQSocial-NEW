import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle, AlertCircle, XCircle, RefreshCw } from "lucide-react";
import { useLocation } from "wouter";

interface PlatformConnection {
  platform: string;
  connected: boolean;
  status: 'healthy' | 'warning' | 'error';
  lastRefresh?: string;
  tokenExpiry?: string;
}

export function PlatformStatusWidget() {
  const [, setLocation] = useLocation();
  
  const { data: connections, isLoading, refetch } = useQuery<PlatformConnection[]>({
    queryKey: ['/api/platform-connections'],
    select: (data: any[]) => {
      // Transform the API response to match our expected interface
      return data.map(conn => ({
        platform: conn.platform,
        connected: conn.isActive, // Use database isActive status
        status: conn.oauthStatus?.isValid ? 'healthy' : (conn.oauthStatus?.needsRefresh ? 'warning' : 'error'),
        lastRefresh: conn.connectedAt,
        tokenExpiry: conn.oauthStatus?.expiresAt
      }));
    },
    refetchInterval: 60000 // Refresh every minute
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'warning': return <AlertCircle className="w-4 h-4 text-yellow-500" />;
      case 'error': return <XCircle className="w-4 h-4 text-red-500" />;
      default: return <XCircle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'bg-green-100 text-green-800';
      case 'warning': return 'bg-yellow-100 text-yellow-800';
      case 'error': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const platformDisplayNames = {
    facebook: 'Facebook',
    instagram: 'Instagram',
    linkedin: 'LinkedIn',
    youtube: 'YouTube',
    twitter: 'X (Twitter)'
  };

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center space-x-2">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span className="text-sm text-gray-600">Checking platform connections...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  const healthyCount = connections?.filter(c => c.status === 'healthy').length || 0;
  const totalCount = connections?.length || 0;

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium">Platform Connections</CardTitle>
          <Badge variant="outline" className="text-xs">
            {healthyCount}/{totalCount} Connected
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="space-y-2">
          {connections?.map((connection) => (
            <div key={connection.platform} className="flex items-center justify-between p-2 rounded-lg bg-gray-50">
              <div className="flex items-center space-x-3">
                {getStatusIcon(connection.status)}
                <span className="text-sm font-medium">
                  {platformDisplayNames[connection.platform as keyof typeof platformDisplayNames] || connection.platform}
                </span>
              </div>
              <Badge className={`text-xs ${getStatusColor(connection.status)}`}>
                {connection.connected ? connection.status : 'disconnected'}
              </Badge>
            </div>
          ))}
        </div>
        
        <div className="mt-4 flex space-x-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => refetch()}
            aria-label="Refresh platform connection status"
            className="flex-1"
          >
            <RefreshCw className="w-3 h-3 mr-1" />
            Refresh
          </Button>
          <Button
            size="sm"
            onClick={() => setLocation('/token-status')}
            aria-label="Manage platform connections"
            className="flex-1"
          >
            Manage
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}