import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { ExternalLink, Instagram, CheckCircle, XCircle } from 'lucide-react';
import MasterHeader from '@/components/master-header';
import MasterFooter from '@/components/master-footer';

interface InstagramStatus {
  canPost: boolean;
  error?: string;
  accountType?: string;
}

interface InstagramFix {
  authUrl: string;
  currentStatus: InstagramStatus;
  message: string;
}

export default function InstagramFix() {
  const [instagramData, setInstagramData] = useState<InstagramFix | null>(null);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState(false);

  const loadInstagramStatus = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/instagram-fix');
      if (response.ok) {
        const data = await response.json();
        setInstagramData(data.instagram);
      }
    } catch (error) {
      console.error('Instagram status error:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInstagramStatus();
  }, []);

  const connectInstagram = () => {
    if (!instagramData?.authUrl) return;
    
    setConnecting(true);
    
    // Open Instagram auth in popup
    const popup = window.open(
      instagramData.authUrl, 
      'instagram_auth', 
      'width=600,height=700,scrollbars=yes,resizable=yes'
    );

    // Monitor popup for completion
    const checkClosed = setInterval(() => {
      if (popup?.closed) {
        clearInterval(checkClosed);
        setConnecting(false);
        // Refresh status after connection
        setTimeout(() => {
          loadInstagramStatus();
        }, 1000);
      }
    }, 1000);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <MasterHeader />
        <div className="container mx-auto px-4 py-8">
          <div className="text-center">Loading Instagram connection status...</div>
        </div>
        <MasterFooter />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <MasterHeader />
      
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-2xl mx-auto space-y-6">
          <div className="text-center">
            <Instagram className="h-16 w-16 mx-auto mb-4 text-pink-600" />
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
              Instagram Business Connection
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              Connect your Instagram Business account to start posting
            </p>
          </div>

          {instagramData && (
            <>
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    {instagramData.currentStatus.canPost ? (
                      <>
                        <CheckCircle className="h-5 w-5 text-green-600" />
                        Instagram Connected
                      </>
                    ) : (
                      <>
                        <XCircle className="h-5 w-5 text-red-600" />
                        Instagram Not Connected
                      </>
                    )}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="mb-4">{instagramData.message}</p>
                  
                  {instagramData.currentStatus.error && (
                    <Alert className="mb-4">
                      <AlertDescription>
                        <strong>Issue:</strong> {instagramData.currentStatus.error}
                      </AlertDescription>
                    </Alert>
                  )}

                  {!instagramData.currentStatus.canPost && (
                    <div className="space-y-4">
                      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <h4 className="font-semibold mb-2">Requirements for Instagram posting:</h4>
                        <ul className="list-disc list-inside text-sm space-y-1">
                          <li>Instagram Business or Creator account</li>
                          <li>Instagram connected to a Facebook Page</li>
                          <li>Page admin permissions</li>
                          <li>Content publishing permissions</li>
                        </ul>
                      </div>

                      <Button 
                        onClick={connectInstagram}
                        disabled={connecting}
                        className="w-full flex items-center justify-center gap-2"
                        size="lg"
                      >
                        <ExternalLink className="h-5 w-5" />
                        {connecting ? 'Connecting...' : 'Connect Instagram Business'}
                      </Button>
                    </div>
                  )}

                  {instagramData.currentStatus.canPost && (
                    <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                      <p className="text-green-800 dark:text-green-200">
                        Instagram Business account connected successfully! Your posts will now publish to Instagram.
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Troubleshooting</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 text-sm">
                    <div>
                      <strong>If connection fails:</strong>
                      <ul className="list-disc list-inside ml-4 mt-1">
                        <li>Ensure you have an Instagram Business account</li>
                        <li>Connect your Instagram to a Facebook Page first</li>
                        <li>Make sure you're the admin of the Facebook Page</li>
                        <li>Grant all requested permissions during auth</li>
                      </ul>
                    </div>
                    
                    <div>
                      <strong>Instagram posting requirements:</strong>
                      <ul className="list-disc list-inside ml-4 mt-1">
                        <li>Images must be 1080x1080 pixels minimum</li>
                        <li>Videos up to 60 seconds for feed posts</li>
                        <li>Text captions up to 2,200 characters</li>
                        <li>Hashtags and mentions supported</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <div className="text-center">
                <Button onClick={loadInstagramStatus} variant="outline">
                  Refresh Status
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