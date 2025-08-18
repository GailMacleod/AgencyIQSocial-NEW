import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CheckIcon } from "lucide-react";
import { SiFacebook, SiInstagram, SiLinkedin, SiYoutube, SiX } from "react-icons/si";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { trackMilestone } from "@/lib/analytics";

export default function PlatformConnections() {
  const [location, setLocation] = useLocation();
  const { toast } = useToast();
  const [loading, setLoading] = useState<string | null>(null);
  const [connectedPlatforms, setConnectedPlatforms] = useState<{[key: string]: boolean}>({});

  // Fetch existing platform connections
  const { data: connections = [], isLoading: connectionsLoading } = useQuery({
    queryKey: ["/api/platform-connections"],
  });

  // Fetch session connection state
  const { data: sessionState } = useQuery({
    queryKey: ['/api/get-connection-state'],
    retry: 2
  });

  // Initialize connection state from session
  useEffect(() => {
    if (sessionState?.connectedPlatforms) {
      setConnectedPlatforms(sessionState.connectedPlatforms);
    }
  }, [sessionState]);

  // Check live platform status on component load
  useEffect(() => {
    const validPlatforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
    validPlatforms.forEach(plat => {
      fetch('/api/check-live-status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ platform: plat })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          setConnectedPlatforms(prev => ({
            ...prev,
            [data.platform]: data.isConnected
          }));
        }
      })
      .catch(err => console.warn(`Live status check failed for ${plat}:`, err));
    });
  }, []);

  const connectedPlatformsList = Array.isArray(connections) ? connections.map((conn: any) => conn.platform) : [];

  // Check localStorage tokens on page load
  useEffect(() => {
    console.log('Checking disconnect status');
    const tokenKeys = Object.keys(localStorage).filter(key => key.startsWith('token_'));
    console.log('LocalStorage tokens found:', tokenKeys);
    tokenKeys.forEach(key => {
      console.log(`${key}: ${localStorage.getItem(key)}`);
    });
  }, []);

  // Handle OAuth callback messages
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const connected = urlParams.get('connected');
    const error = urlParams.get('error');
    
    if (connected) {
      toast({
        title: "Platform Connected",
        description: `${connected} has been connected successfully`,
      });
      // Clear URL parameters
      window.history.replaceState({}, '', '/platform-connections');
    }
    
    if (error) {
      toast({
        title: "Connection Failed",
        description: `Failed to connect platform: ${error.replace(/_/g, ' ')}`,
        variant: "destructive",
      });
      // Clear URL parameters
      window.history.replaceState({}, '', '/platform-connections');
    }
  }, [toast]);

  const platforms = [
    { id: 'facebook', name: 'facebook', icon: SiFacebook, color: 'platform-facebook' },
    { id: 'instagram', name: 'instagram', icon: SiInstagram, color: 'platform-instagram' },
    { id: 'linkedin', name: 'linkedin', icon: SiLinkedin, color: 'platform-linkedin' },
    { id: 'youtube', name: 'youtube', icon: SiYoutube, color: 'platform-youtube' },
    { id: 'x', name: 'x (twitter)', icon: SiX, color: 'platform-x' },
  ];

  const connectPlatform = async (platformId: string) => {
    setLoading(platformId);
    console.log(`Connecting platform: ${platformId}`);
    
    // Get platform-specific credentials from user
    const platform = platforms.find(p => p.id === platformId);
    let username = '';
    let password = '';
    
    if (platformId === 'facebook' || platformId === 'instagram') {
      username = window.prompt(`Enter your ${platform?.name} email or phone:`) || '';
      password = window.prompt(`Enter your ${platform?.name} password:`) || '';
    } else if (platformId === 'linkedin') {
      username = window.prompt(`Enter your LinkedIn email:`) || '';
      password = window.prompt(`Enter your LinkedIn password:`) || '';
    } else if (platformId === 'youtube') {
      username = window.prompt(`Enter your Google email (for YouTube):`) || '';
      password = window.prompt(`Enter your Google password:`) || '';
    } else if (platformId === 'x') {
      username = window.prompt(`Enter your X (Twitter) username or email:`) || '';
      password = window.prompt(`Enter your X (Twitter) password:`) || '';
    }
    
    if (!username || !password) {
      setLoading(null);
      return;
    }
    
    try {
      const response = await apiRequest("POST", "/api/connect-platform", {
        platform: platformId,
        username,
        password
      });
      
      // Log successful connection
      console.log(`✅ Successfully connected to ${platformId}`);
      
      // The connection is handled server-side via OAuth
      // No client-side token storage needed
      
      toast({
        title: "Platform Connected",
        description: `${platform?.name} has been connected successfully`,
      });
      
      // Track platform connection milestone
      trackMilestone(`platform_connected_${platformId}`);
      
      // Refresh the page to show updated connections
      window.location.reload();
      
    } catch (error: any) {
      console.log(`token_${platformId}: error - ${error.message || 'connection failed'}`);
      toast({
        title: "Connection Failed",
        description: error.message || `Failed to connect ${platform?.name}`,
        variant: "destructive",
      });
    } finally {
      setLoading(null);
    }
  };

  const disconnectPlatform = async (platformId: string) => {
    setLoading(platformId);
    console.log(`Disconnecting platform: ${platformId}`);
    
    try {
      const response = await fetch('/api/disconnect-platform', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ platform: platformId })
      });
      
      const data = await response.json();
      
      if (data.success) {
        // Update local state based on backend response
        if (data.action === 'syncState' && data.version === '1.3') {
          setConnectedPlatforms(prev => ({
            ...prev,
            [data.platform]: data.isConnected
          }));
        }
        
        // Remove token from localStorage
        localStorage.removeItem(`token_${platformId}`);
        console.log(`token_${platformId}: removed from localStorage`);
        
        toast({
          title: "Platform Disconnected",
          description: `${platformId} has been disconnected successfully`,
        });
      } else {
        throw new Error(data.error || 'Disconnect failed');
      }
      
    } catch (error: any) {
      console.log(`disconnect_${platformId}: error - ${error.message || 'disconnection failed'}`);
      toast({
        title: "Disconnection Failed",
        description: error.message || `Failed to disconnect ${platformId}`,
        variant: "destructive",
      });
    } finally {
      setLoading(null);
    }
  };

  const handleNext = () => {
    // Track analytics milestone when navigating to analytics
    trackMilestone('platforms_connected_analytics_viewed');
    setLocation("/analytics");
  };

  return (
    <div className="min-h-screen bg-background">
      <MasterHeader />
      
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="text-center mb-8">
          <p className="text-sm text-foreground lowercase">step 3 of 3</p>
          <div className="w-full bg-muted rounded-full h-2 mt-2">
            <div className="bg-primary h-2 rounded-full w-full"></div>
          </div>
        </div>

        <Card className="card-agencyiq">
          <CardContent className="p-8">
            <h2 className="text-heading font-light text-foreground text-center mb-8 lowercase">
              connect your platforms
            </h2>
            
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
              {platforms.map((platform) => {
                const isConnected = connectedPlatforms[platform.id] === true || connectedPlatformsList.includes(platform.id);
                const isLoading = loading === platform.id;
                const Icon = platform.icon;

                return (
                  <div
                    key={platform.id}
                    className={`relative border rounded-xl p-4 text-center transition-all duration-200 ${
                      isConnected 
                        ? 'border-[#3250fa]/30 bg-[#3250fa]/10 shadow-sm' 
                        : 'border-gray-200 hover:border-gray-300 hover:shadow-sm'
                    }`}
                  >
                    {/* Success tick overlay */}
                    {isConnected && (
                      <div className="absolute -top-2 -right-2 w-6 h-6 bg-[#3250fa] rounded-full flex items-center justify-center shadow-md">
                        <CheckIcon className="w-4 h-4 text-white" />
                      </div>
                    )}
                    
                    <div className={`w-10 h-10 ${platform.color} rounded-lg flex items-center justify-center mx-auto mb-3`}>
                      <Icon className="w-5 h-5 text-white" />
                    </div>
                    <h3 className="font-medium text-foreground mb-3 text-sm lowercase">{platform.name}</h3>
                    
                    {/* YouTube video creation reminder */}
                    {platform.id === 'youtube' && (
                      <p className="text-xs text-gray-500 mb-3">
                        *Create a 30s video yourself and add it to your YouTube.
                      </p>
                    )}
                    
                    {isConnected ? (
                      <div className="space-y-2">
                        <Button
                          disabled
                          className="w-full bg-[#3250fa]/10 text-[#3250fa] cursor-not-allowed text-xs py-2 h-8 border border-[#3250fa]/20"
                          variant="outline"
                        >
                          connected
                        </Button>
                        <Button
                          onClick={() => disconnectPlatform(platform.id)}
                          className="w-full text-xs py-2 h-8 text-white bg-[#ff538f] hover:bg-[#e04880] border-[#ff538f]"
                          variant="outline"
                          disabled={isLoading}
                        >
                          {isLoading ? 'disconnecting...' : 'disconnect'}
                        </Button>
                      </div>
                    ) : (
                      <Button
                        onClick={() => connectPlatform(platform.id)}
                        className="w-full text-xs py-2 h-8"
                        variant="outline"
                        disabled={isLoading}
                      >
                        {isLoading ? 'connecting...' : 'connect'}
                      </Button>
                    )}
                  </div>
                );
              })}
            </div>

            <div className="text-center">
              <Button
                onClick={handleNext}
                className="btn-secondary px-8 py-3"
                disabled={connectedPlatformsList.length === 0 && Object.values(connectedPlatforms).every(val => !val)}
              >
                next
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <MasterFooter />
    </div>
  );
}
