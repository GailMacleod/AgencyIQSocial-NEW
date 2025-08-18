import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle, AlertTriangle, Activity, Facebook, Instagram } from "lucide-react";
import { MetaPixelTracker } from "@/lib/meta-pixel";
import { FacebookSDK, AgencyIQFacebookTracking } from "@/lib/facebook-sdk";

interface PixelStatus {
  isLoaded: boolean;
  appId: string;
  eventsTracked: number;
  lastEventTime: string | null;
  errors: string[];
  facebookSDK: {
    isInitialized: boolean;
    isAvailable: boolean;
    fbExists: boolean;
    appEventsExists: boolean;
  };
}

export default function MetaPixelStatus() {
  const [status, setStatus] = useState<PixelStatus>({
    isLoaded: false,
    appId: "1409057863445071",
    eventsTracked: 0,
    lastEventTime: null,
    errors: [],
    facebookSDK: {
      isInitialized: false,
      isAvailable: false,
      fbExists: false,
      appEventsExists: false
    }
  });

  useEffect(() => {
    // Check if Meta Pixel and Facebook SDK are properly loaded
    const checkPixelStatus = () => {
      const isLoaded = typeof window !== 'undefined' && 
                     window.fbq && 
                     typeof window.fbq === 'function';
      
      // Get Facebook SDK status
      const facebookSDKStatus = FacebookSDK.getStatus();
      
      setStatus(prev => ({
        ...prev,
        isLoaded,
        lastEventTime: new Date().toISOString(),
        facebookSDK: facebookSDKStatus
      }));

      if (isLoaded) {
        // Track the status check itself
        MetaPixelTracker.trackCustomEvent('PixelStatusCheck', {
          status: 'loaded',
          app_id: '1409057863445071',
          check_time: new Date().toISOString(),
          facebook_sdk_available: facebookSDKStatus.isAvailable
        });
      }
    };

    checkPixelStatus();
    
    // Check status every 30 seconds
    const interval = setInterval(checkPixelStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const testPixelEvent = async () => {
    try {
      // Test Meta Pixel
      MetaPixelTracker.trackCustomEvent('ManualPixelTest', {
        test_type: 'status_component',
        timestamp: new Date().toISOString(),
        user_initiated: true
      });
      
      // Test Facebook SDK
      await FacebookSDK.logEvent('TestEvent', {
        source: 'status_component',
        timestamp: new Date().toISOString()
      });
      
      setStatus(prev => ({
        ...prev,
        eventsTracked: prev.eventsTracked + 1,
        lastEventTime: new Date().toISOString()
      }));
    } catch (error: any) {
      setStatus(prev => ({
        ...prev,
        errors: [...prev.errors, error.message]
      }));
    }
  };

  const testSubscriptionTracking = async () => {
    try {
      await AgencyIQFacebookTracking.trackSubscriptionPurchase('Pro', 97);
      setStatus(prev => ({
        ...prev,
        eventsTracked: prev.eventsTracked + 1,
        lastEventTime: new Date().toISOString()
      }));
    } catch (error: any) {
      setStatus(prev => ({
        ...prev,
        errors: [...prev.errors, `Subscription test: ${error.message}`]
      }));
    }
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center space-x-2">
            <Facebook className="h-5 w-5 text-blue-600" />
            <span>Meta Pixel Status</span>
          </CardTitle>
          <Badge variant={status.isLoaded ? "default" : "destructive"}>
            {status.isLoaded ? "Active" : "Inactive"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              {status.isLoaded ? (
                <CheckCircle className="h-4 w-4 text-green-500" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-red-500" />
              )}
              <span className="text-sm font-medium">
                Pixel Loaded: {status.isLoaded ? "Yes" : "No"}
              </span>
            </div>
            
            <div className="text-sm text-muted-foreground">
              App ID: {status.appId}
            </div>
            
            <div className="flex items-center space-x-2">
              <Activity className="h-4 w-4 text-blue-500" />
              <span className="text-sm">
                Events Tracked: {status.eventsTracked}
              </span>
            </div>
          </div>
          
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <Instagram className="h-4 w-4 text-pink-500" />
              <span className="text-sm font-medium">
                Facebook SDK Status
              </span>
            </div>
            
            <div className="text-xs space-y-1">
              <div className="flex items-center space-x-2">
                {status.facebookSDK.isAvailable ? (
                  <CheckCircle className="h-3 w-3 text-green-500" />
                ) : (
                  <AlertTriangle className="h-3 w-3 text-red-500" />
                )}
                <span>SDK Available: {status.facebookSDK.isAvailable ? "Yes" : "No"}</span>
              </div>
              <div className="flex items-center space-x-2">
                {status.facebookSDK.fbExists ? (
                  <CheckCircle className="h-3 w-3 text-green-500" />
                ) : (
                  <AlertTriangle className="h-3 w-3 text-red-500" />
                )}
                <span>FB Object: {status.facebookSDK.fbExists ? "Loaded" : "Missing"}</span>
              </div>
            </div>
            
            {status.lastEventTime && (
              <div className="text-sm text-muted-foreground">
                Last Event: {new Date(status.lastEventTime).toLocaleTimeString()}
              </div>
            )}
            
            <div className="flex space-x-2">
              <button
                onClick={testPixelEvent}
                className="text-xs bg-blue-100 hover:bg-blue-200 text-blue-800 px-2 py-1 rounded"
              >
                Test Event
              </button>
              <button
                onClick={testSubscriptionTracking}
                className="text-xs bg-green-100 hover:bg-green-200 text-green-800 px-2 py-1 rounded"
              >
                Test Purchase
              </button>
            </div>
          </div>
        </div>
        
        {status.errors.length > 0 && (
          <div className="mt-4 p-3 bg-red-50 rounded-lg">
            <h4 className="text-sm font-medium text-red-800 mb-2">Errors:</h4>
            <ul className="text-xs text-red-700 space-y-1">
              {status.errors.map((error, index) => (
                <li key={index}>• {error}</li>
              ))}
            </ul>
          </div>
        )}
        
        <div className="mt-4 p-3 bg-blue-50 rounded-lg">
          <h4 className="text-sm font-medium text-blue-800 mb-2">Integration Features:</h4>
          <ul className="text-xs text-blue-700 space-y-1">
            <li>• Subscription purchase tracking</li>
            <li>• Gift certificate redemption events</li>
            <li>• User registration and lead generation</li>
            <li>• Post approval and content generation</li>
            <li>• Platform connection monitoring</li>
            <li>• Analytics view tracking</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}