import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import BackButton from "@/components/back-button";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";
import { 
  Facebook, 
  Instagram, 
  Linkedin, 
  Youtube, 
  Loader2,
  CheckCircle,
  AlertCircle,
  Clock
} from "lucide-react";
import { SiX } from "react-icons/si";

interface PlatformConnection {
  id: number;
  platform: string;
  platformUsername: string;
  isActive: boolean;
  createdAt: string;
}

const platforms = [
  {
    id: 'facebook',
    name: 'Facebook',
    icon: Facebook,
    color: 'bg-blue-600',
    approved: true,
    description: 'Connect your Facebook business page for content publishing'
  },
  {
    id: 'instagram',
    name: 'Instagram',
    icon: Instagram,
    color: 'bg-pink-600',
    approved: true,
    description: 'Share photos and stories to your Instagram business account'
  },
  {
    id: 'linkedin',
    name: 'LinkedIn',
    icon: Linkedin,
    color: 'bg-blue-700',
    approved: true,
    description: 'Post professional content to your LinkedIn profile'
  },
  {
    id: 'x',
    name: 'X (Twitter)',
    icon: SiX,
    color: 'bg-black',
    approved: true,
    description: 'Tweet and engage with your Twitter audience'
  },
  {
    id: 'youtube',
    name: 'YouTube',
    icon: Youtube,
    color: 'bg-red-600',
    approved: true,
    description: 'Upload videos and manage your YouTube channel'
  },

];

export default function RealPlatformConnections() {
  const [loading, setLoading] = useState<string | null>(null);
  const { toast } = useToast();

  const { data: connections = [], refetch } = useQuery({
    queryKey: ["/api/platform-connections"],
    queryFn: async (): Promise<PlatformConnection[]> => {
      const response = await fetch("/api/platform-connections", {
        credentials: 'include'
      });
      if (!response.ok) throw new Error('Failed to fetch connections');
      return response.json();
    }
  });

  // Check for OAuth callback success/error messages
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const success = urlParams.get('success');
    const error = urlParams.get('error');

    if (success) {
      const platform = success.replace('_connected', '');
      toast({
        title: "Platform Connected",
        description: `${platform.charAt(0).toUpperCase() + platform.slice(1)} has been connected successfully`,
      });
      // Clean URL
      window.history.replaceState({}, '', '/platform-connections');
      refetch();
    }

    if (error) {
      const platform = error.replace('_failed', '');
      toast({
        title: "Connection Failed",
        description: `Failed to connect ${platform.charAt(0).toUpperCase() + platform.slice(1)}`,
        variant: "destructive",
      });
      // Clean URL
      window.history.replaceState({}, '', '/platform-connections');
    }
  }, [toast, refetch]);

  const connectPlatform = async (platformId: string) => {
    const platform = platforms.find(p => p.id === platformId);
    setLoading(platformId);

    if (!platform?.approved) {
      toast({
        title: "OAuth Approval Pending",
        description: `${platform?.name} OAuth is awaiting platform approval`,
        variant: "default",
      });
      setLoading(null);
      return;
    }

    try {
      const response = await apiRequest("POST", "/api/platform-connections/connect", {
        platform: platformId
      }) as { redirectUrl?: string };

      if (response.redirectUrl) {
        // Redirect to OAuth flow
        window.location.href = response.redirectUrl;
        return;
      }

    } catch (error: any) {
      toast({
        title: "Connection Failed",
        description: error.message || `Failed to initiate ${platform?.name} connection`,
        variant: "destructive",
      });
      setLoading(null);
    }
  };

  const disconnectPlatform = async (platformId: string) => {
    setLoading(platformId);

    try {
      await apiRequest("DELETE", `/api/platform-connections/${platformId}`, {});
      
      toast({
        title: "Platform Disconnected",
        description: "Platform has been disconnected successfully",
      });
      
      refetch();
    } catch (error: any) {
      toast({
        title: "Disconnect Failed",
        description: error.message || "Failed to disconnect platform",
        variant: "destructive",
      });
    } finally {
      setLoading(null);
    }
  };

  const isConnected = (platformId: string) => {
    return connections.some((conn: PlatformConnection) => 
      conn.platform === platformId && conn.isActive
    );
  };

  const getConnectionInfo = (platformId: string) => {
    return connections.find((conn: PlatformConnection) => 
      conn.platform === platformId && conn.isActive
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <MasterHeader showUserMenu={true} title="Platform Connections" />
      
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          <BackButton to="/analytics" />
          
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Connect Your Social Media</h1>
            <p className="text-gray-600">
              Connect your social media accounts to enable automated content publishing and analytics tracking.
            </p>
          </div>

          <div className="connect-section grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {platforms.map((platform) => {
              const Icon = platform.icon;
              const connected = isConnected(platform.id);
              const connectionInfo = getConnectionInfo(platform.id);
              const isLoading = loading === platform.id;

              return (
                <Card key={platform.id} className="relative overflow-hidden">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2 rounded-lg ${platform.color}`}>
                          <Icon className="h-6 w-6 text-white" />
                        </div>
                        <div>
                          <CardTitle className="text-lg">{platform.name}</CardTitle>
                          <div className="flex items-center space-x-2 mt-1">
                            {platform.approved ? (
                              <Badge variant="default" className="bg-[#3250fa]/10 text-[#3250fa]">
                                <CheckCircle className="h-3 w-3 mr-1" />
                                OAuth Approved
                              </Badge>
                            ) : (
                              <Badge variant="secondary" className="bg-orange-100 text-orange-800">
                                <Clock className="h-3 w-3 mr-1" />
                                Pending Approval
                              </Badge>
                            )}
                          </div>
                        </div>
                      </div>

                      {connected && (
                        <div className="flex items-center space-x-1">
                          <CheckCircle className="h-5 w-5 text-[#3250fa]" />
                          <span className="text-sm font-medium text-[#3250fa]">Connected</span>
                        </div>
                      )}
                    </div>
                  </CardHeader>

                  <CardContent>
                    <CardDescription className="mb-4 text-sm">
                      {platform.description}
                    </CardDescription>

                    {connected && connectionInfo && (
                      <div className="mb-4 p-3 bg-[#3250fa]/10 rounded-lg border border-[#3250fa]/20">
                        <p className="text-sm text-[#3250fa]">
                          <strong>Account:</strong> {connectionInfo.platformUsername}
                        </p>
                        <p className="text-xs text-[#3250fa]/80 mt-1">
                          Connected {new Date(connectionInfo.createdAt).toLocaleDateString()}
                        </p>
                      </div>
                    )}



                    <div className="flex space-x-2">
                      {connected ? (
                        <Button
                          size="sm"
                          onClick={() => disconnectPlatform(platform.id)}
                          disabled={isLoading}
                          className="connect-button flex-1 text-white bg-[#ff538f] hover:bg-[#e04880] border-[#ff538f]"
                        >
                          {isLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                          Disconnect
                        </Button>
                      ) : (
                        <Button
                          onClick={() => connectPlatform(platform.id)}
                          disabled={isLoading || !platform.approved}
                          className="connect-button flex-1"
                          variant={platform.approved ? "default" : "secondary"}
                        >
                          {isLoading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                          {platform.approved ? "Connect with OAuth" : "OAuth Pending"}
                        </Button>
                      )}
                    </div>

                    {!platform.approved && (
                      <p className="text-xs text-gray-500 mt-2 text-center">
                        Awaiting {platform.name} OAuth API approval
                      </p>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <div className="mt-8 p-6 bg-blue-50 rounded-lg border border-blue-200">
            <div className="flex items-start space-x-3">
              <AlertCircle className="h-6 w-6 text-blue-600 mt-0.5" />
              <div>
                <h3 className="font-medium text-blue-900 mb-2">OAuth Security Notice</h3>
                <p className="text-sm text-blue-800 mb-3">
                  We use official OAuth 2.0 authentication to securely connect your social media accounts. 
                  Your credentials are never stored on our servers - only secure access tokens are used.
                </p>
                <div className="space-y-1 text-xs text-blue-700">
                  <p>✓ Facebook & Instagram: Business API access for posts and analytics</p>
                  <p>✓ LinkedIn: Professional content publishing and engagement metrics</p>
                  <p>✓ X (Twitter): Tweet publishing and audience analytics</p>
                  <p>✓ YouTube: Video management and channel analytics</p>

                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <MasterFooter />
    </div>
  );
}