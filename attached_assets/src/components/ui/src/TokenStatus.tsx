import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { CheckCircle, XCircle, AlertTriangle, RefreshCw } from 'lucide-react';
import MasterHeader from '@/components/master-header';
import MasterFooter from '@/components/master-footer';

interface TokenValidation {
  valid: boolean;
  error?: string;
  needsReconnection: boolean;
  permissions?: string[];
}

interface ValidationResults {
  [platform: string]: TokenValidation;
}

export default function TokenStatus() {
  const [validationResults, setValidationResults] = useState<ValidationResults>({});
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState<any>(null);

  const loadTokenStatus = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/validate-tokens');
      const data = await response.json();
      
      if (data.success) {
        setValidationResults(data.validationResults);
        setSummary(data.summary);
      }
    } catch (error) {
      console.error('Failed to load token status:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTokenStatus();
  }, []);

  const getStatusIcon = (validation: TokenValidation) => {
    if (validation.valid) {
      return <CheckCircle className="h-5 w-5 text-green-600" />;
    } else if (validation.needsReconnection) {
      return <XCircle className="h-5 w-5 text-red-600" />;
    } else {
      return <AlertTriangle className="h-5 w-5 text-yellow-600" />;
    }
  };

  const getStatusBadge = (validation: TokenValidation) => {
    if (validation.valid) {
      return <Badge variant="default" className="bg-green-100 text-green-800">Valid</Badge>;
    } else if (validation.needsReconnection) {
      return <Badge variant="destructive">Needs Reconnection</Badge>;
    } else {
      return <Badge variant="secondary">Warning</Badge>;
    }
  };

  const platformDisplayNames: { [key: string]: string } = {
    facebook: 'Facebook',
    linkedin: 'LinkedIn',
    twitter: 'X (Twitter)',
    x: 'X (Twitter)',
    instagram: 'Instagram',
    youtube: 'YouTube'
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <MasterHeader />
      
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto space-y-6">
          <div className="text-center">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
              Token Status Check
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              Real-time validation of your social media platform connections
            </p>
          </div>

          {summary && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <RefreshCw className="h-5 w-5" />
                  Connection Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-bold text-blue-600">{summary.totalConnections}</div>
                    <div className="text-sm text-gray-600">Total Connections</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-green-600">{summary.validConnections}</div>
                    <div className="text-sm text-gray-600">Valid Tokens</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-red-600">{summary.needingReconnection}</div>
                    <div className="text-sm text-gray-600">Need Reconnection</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {loading ? (
            <Card>
              <CardContent className="flex items-center justify-center py-8">
                <RefreshCw className="h-6 w-6 animate-spin mr-2" />
                Validating tokens...
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {Object.entries(validationResults).map(([platform, validation]) => (
                <Card key={platform}>
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(validation)}
                        {platformDisplayNames[platform] || platform}
                      </div>
                      {getStatusBadge(validation)}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {validation.error && (
                      <Alert className="mb-4">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>
                          <strong>Error:</strong> {validation.error}
                        </AlertDescription>
                      </Alert>
                    )}
                    
                    {validation.permissions && validation.permissions.length > 0 && (
                      <div className="mb-4">
                        <h4 className="font-semibold mb-2">Current Permissions:</h4>
                        <div className="flex flex-wrap gap-2">
                          {validation.permissions.map((permission) => (
                            <Badge key={permission} variant="outline" className="text-xs">
                              {permission}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {validation.needsReconnection && (
                      <Button 
                        onClick={() => window.location.href = `/oauth-reconnect`}
                        className="mt-2"
                      >
                        Reconnect {platformDisplayNames[platform]}
                      </Button>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          <div className="text-center">
            <Button onClick={loadTokenStatus} variant="outline" disabled={loading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh Status
            </Button>
          </div>
        </div>
      </div>
      
      <MasterFooter />
    </div>
  );
}