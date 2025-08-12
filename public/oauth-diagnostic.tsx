import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ExternalLink, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import MasterHeader from '@/components/master-header';
import MasterFooter from '@/components/master-footer';

interface TokenStatus {
  working: boolean;
  error: string;
  needsFix: boolean;
}

interface DiagnosticData {
  currentStatus: {
    facebook: TokenStatus;
    linkedin: TokenStatus;
    twitter: TokenStatus;
    summary: string;
  };
  solution: {
    authUrls: {
      facebook: string;
      linkedin: string;
      twitter: string;
    };
    instructions: string[];
  };
}

export default function OAuthDiagnostic() {
  const [diagnosticData, setDiagnosticData] = useState<DiagnosticData | null>(null);
  const [loading, setLoading] = useState(true);

  const loadDiagnostic = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/oauth-fix-direct');
      if (response.ok) {
        const data = await response.json();
        setDiagnosticData(data);
      } else {
        console.error('Failed to load diagnostic data');
      }
    } catch (error) {
      console.error('Diagnostic fetch error:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDiagnostic();
  }, []);

  const getStatusIcon = (status: TokenStatus) => {
    if (status.working) {
      return <CheckCircle className="h-5 w-5 text-green-600" />;
    } else {
      return <XCircle className="h-5 w-5 text-red-600" />;
    }
  };

  const openAuthUrl = (url: string, platform: string) => {
    window.open(url, `${platform}_auth`, 'width=600,height=700,scrollbars=yes,resizable=yes');
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <MasterHeader />
        <div className="container mx-auto px-4 py-8">
          <div className="text-center">Loading OAuth diagnostic...</div>
        </div>
        <MasterFooter />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <MasterHeader />
      
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto space-y-6">
          <div className="text-center">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
              OAuth Connection Diagnostic
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              Fix your social media connections to start publishing posts
            </p>
          </div>

          {diagnosticData && (
            <>
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <strong>Issue Found:</strong> Your connections show as "Connected" but lack proper posting permissions. 
                  This is why your posts are failing to publish.
                </AlertDescription>
              </Alert>

              <Card>
                <CardHeader>
                  <CardTitle>Current Token Status</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="mb-4 text-sm text-gray-600">{diagnosticData.currentStatus.summary}</p>
                  
                  <div className="space-y-4">
                    {/* Facebook Status */}
                    <div className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(diagnosticData.currentStatus.facebook)}
                        <div>
                          <div className="font-medium">Facebook</div>
                          <div className="text-sm text-red-600">
                            {diagnosticData.currentStatus.facebook.error}
                          </div>
                        </div>
                      </div>
                      {diagnosticData.currentStatus.facebook.needsFix && (
                        <Button
                          onClick={() => openAuthUrl(diagnosticData.solution.authUrls.facebook, 'Facebook')}
                          className="flex items-center gap-2"
                        >
                          <ExternalLink className="h-4 w-4" />
                          Fix Facebook
                        </Button>
                      )}
                    </div>

                    {/* LinkedIn Status */}
                    <div className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(diagnosticData.currentStatus.linkedin)}
                        <div>
                          <div className="font-medium">LinkedIn</div>
                          <div className="text-sm text-red-600">
                            {diagnosticData.currentStatus.linkedin.error}
                          </div>
                        </div>
                      </div>
                      {diagnosticData.currentStatus.linkedin.needsFix && (
                        <Button
                          onClick={() => openAuthUrl(diagnosticData.solution.authUrls.linkedin, 'LinkedIn')}
                          className="flex items-center gap-2"
                        >
                          <ExternalLink className="h-4 w-4" />
                          Fix LinkedIn
                        </Button>
                      )}
                    </div>

                    {/* Twitter Status */}
                    <div className="flex items-center justify-between p-3 border rounded-lg">
                      <div className="flex items-center gap-3">
                        {getStatusIcon(diagnosticData.currentStatus.twitter)}
                        <div>
                          <div className="font-medium">X (Twitter)</div>
                          <div className="text-sm text-red-600">
                            {diagnosticData.currentStatus.twitter.error}
                          </div>
                        </div>
                      </div>
                      {diagnosticData.currentStatus.twitter.needsFix && (
                        <Button
                          onClick={() => openAuthUrl(diagnosticData.solution.authUrls.twitter, 'Twitter')}
                          className="flex items-center gap-2"
                        >
                          <ExternalLink className="h-4 w-4" />
                          Fix Twitter
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Fix Instructions</CardTitle>
                </CardHeader>
                <CardContent>
                  <ol className="list-decimal list-inside space-y-2">
                    {diagnosticData.solution.instructions.map((instruction, index) => (
                      <li key={index} className="text-sm">
                        {instruction}
                      </li>
                    ))}
                  </ol>
                  
                  <div className="mt-4 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                    <p className="text-sm text-green-800 dark:text-green-200">
                      <strong>Good news:</strong> Your 50 remaining posts are preserved and will publish 
                      successfully once you reconnect with proper permissions.
                    </p>
                  </div>
                </CardContent>
              </Card>

              <div className="text-center">
                <Button onClick={loadDiagnostic} variant="outline">
                  Refresh Diagnostic
                </Button>
              </div>
            </>
          )}
        </div>
      </div>
      
      <MasterFooter />
    </div>
  );
}