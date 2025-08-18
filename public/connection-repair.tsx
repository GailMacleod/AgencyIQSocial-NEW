import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { CheckCircle, XCircle, AlertTriangle, RefreshCw } from 'lucide-react';
import { apiRequest } from '@/lib/queryClient';
import { useToast } from '@/hooks/use-toast';

interface PlatformStatus {
  platform: string;
  status: 'working' | 'needs_reconnection' | 'needs_upgrade';
  issue: string;
  solution: string;
  reconnectUrl?: string;
}

interface RepairData {
  success: boolean;
  diagnosis: string;
  repairInstructions: {
    summary: string;
    platforms: PlatformStatus[];
    immediateActions: string[];
  };
  nextSteps: string[];
}

export default function ConnectionRepair() {
  const [repairData, setRepairData] = useState<RepairData | null>(null);
  const [loading, setLoading] = useState(true);
  const [reconnecting, setReconnecting] = useState<string | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    loadRepairDiagnosis();
  }, []);

  const loadRepairDiagnosis = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/connection-repair', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error(`Failed to load diagnosis: ${response.status}`);
      }
      
      const data = await response.json();
      setRepairData(data);
    } catch (error: any) {
      toast({
        title: "Error loading diagnosis",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleReconnect = async (platform: string, url?: string) => {
    if (!url) {
      toast({
        title: "Reconnection needed",
        description: `Please contact support for ${platform} reconnection`,
        variant: "default"
      });
      return;
    }

    setReconnecting(platform);
    
    // Redirect to OAuth flow
    window.location.href = url;
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'working':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'needs_reconnection':
        return <XCircle className="h-5 w-5 text-red-500" />;
      case 'needs_upgrade':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      default:
        return <XCircle className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'working':
        return 'bg-green-100 text-green-800';
      case 'needs_reconnection':
        return 'bg-red-100 text-red-800';
      case 'needs_upgrade':
        return 'bg-yellow-100 text-yellow-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return (
      <div className="container mx-auto p-6">
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin" />
          <span className="ml-2">Diagnosing platform connections...</span>
        </div>
      </div>
    );
  }

  if (!repairData) {
    return (
      <div className="container mx-auto p-6">
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Unable to load connection diagnosis. Please try again.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="mb-6">
        <h1 className="text-3xl font-bold mb-2">Connection Repair Center</h1>
        <p className="text-gray-600">
          Diagnose and fix your social media platform connections for successful post publishing
        </p>
      </div>

      {/* Diagnosis Summary */}
      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          <div className="whitespace-pre-line font-mono text-sm">
            {repairData.diagnosis}
          </div>
        </AlertDescription>
      </Alert>

      {/* Platform Status Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {repairData.repairInstructions.platforms.map((platform) => (
          <Card key={platform.platform} className="relative">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg flex items-center gap-2">
                  {getStatusIcon(platform.status)}
                  {platform.platform}
                </CardTitle>
                <Badge className={getStatusColor(platform.status)}>
                  {platform.status.replace('_', ' ')}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <h4 className="font-medium text-red-600 mb-1">Issue:</h4>
                <p className="text-sm text-gray-600">{platform.issue}</p>
              </div>
              
              <div>
                <h4 className="font-medium text-blue-600 mb-1">Solution:</h4>
                <p className="text-sm text-gray-600">{platform.solution}</p>
              </div>

              {platform.reconnectUrl && (
                <Button 
                  onClick={() => handleReconnect(platform.platform, platform.reconnectUrl)}
                  disabled={reconnecting === platform.platform}
                  className="w-full"
                  variant={platform.status === 'working' ? 'outline' : 'default'}
                >
                  {reconnecting === platform.platform ? (
                    <>
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      Reconnecting...
                    </>
                  ) : (
                    'Reconnect Platform'
                  )}
                </Button>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Immediate Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Immediate Actions Required</CardTitle>
          <CardDescription>
            Complete these steps to restore post publishing functionality
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2">
            {repairData.repairInstructions.immediateActions.map((action, index) => (
              <li key={index} className="flex items-start gap-2">
                <span className="bg-blue-100 text-blue-800 text-xs font-medium px-2 py-1 rounded-full min-w-[24px] text-center">
                  {index + 1}
                </span>
                <span className="text-sm">{action}</span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      {/* Next Steps */}
      <Card>
        <CardHeader>
          <CardTitle>Next Steps</CardTitle>
          <CardDescription>
            Follow these steps after reconnecting your platforms
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2">
            {repairData.nextSteps.map((step, index) => (
              <li key={index} className="flex items-start gap-2">
                <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm">{step}</span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      {/* Refresh Button */}
      <div className="flex justify-center">
        <Button onClick={loadRepairDiagnosis} variant="outline">
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh Diagnosis
        </Button>
      </div>
    </div>
  );
}