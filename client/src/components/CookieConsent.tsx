import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { X, Settings, Shield, BarChart3 } from 'lucide-react';

interface CookiePreferences {
  essential: boolean;
  analytics: boolean;
  accepted: boolean;
}

export function CookieConsent() {
  const [showBanner, setShowBanner] = useState(false);
  const [showPreferences, setShowPreferences] = useState(false);
  const [preferences, setPreferences] = useState<CookiePreferences>({
    essential: true, // Always required
    analytics: false,
    accepted: false
  });

  useEffect(() => {
    // Check if user has already made a choice
    const cookieConsent = localStorage.getItem('cookieConsent');
    if (!cookieConsent) {
      setShowBanner(true);
    } else {
      setPreferences(JSON.parse(cookieConsent));
    }
  }, []);

  const setCookieHeader = (prefs: CookiePreferences) => {
    // Set consent cookie that backend can read
    document.cookie = `cookie-consent=${encodeURIComponent(JSON.stringify(prefs))}; path=/; max-age=${365*24*60*60}; samesite=strict${window.location.protocol === 'https:' ? '; secure' : ''}`;
  };

  const acceptAll = () => {
    const newPrefs = { essential: true, analytics: true, accepted: true };
    setPreferences(newPrefs);
    localStorage.setItem('cookieConsent', JSON.stringify(newPrefs));
    setCookieHeader(newPrefs);
    setShowBanner(false);
    console.log('🍪 All cookies accepted');
  };

  const acceptEssential = () => {
    const newPrefs = { essential: true, analytics: false, accepted: true };
    setPreferences(newPrefs);
    localStorage.setItem('cookieConsent', JSON.stringify(newPrefs));
    setCookieHeader(newPrefs);
    setShowBanner(false);
    console.log('🍪 Essential cookies only accepted');
  };

  const savePreferences = () => {
    const newPrefs = { ...preferences, accepted: true };
    setPreferences(newPrefs);
    localStorage.setItem('cookieConsent', JSON.stringify(newPrefs));
    setCookieHeader(newPrefs);
    setShowBanner(false);
    setShowPreferences(false);
    console.log('🍪 Cookie preferences saved:', newPrefs);
  };

  const revokeConsent = () => {
    localStorage.removeItem('cookieConsent');
    setPreferences({ essential: true, analytics: false, accepted: false });
    setShowBanner(true);
    console.log('🍪 Cookie consent revoked');
  };

  if (!showBanner) {
    return (
      <Button 
        variant="outline" 
        size="sm" 
        onClick={revokeConsent}
        className="fixed bottom-4 right-4 z-50 text-xs opacity-70 hover:opacity-100"
      >
        Cookie Settings
      </Button>
    );
  }

  return (
    <div className="fixed bottom-0 left-0 right-0 z-50 p-4 bg-white/95 dark:bg-gray-900/95 backdrop-blur border-t shadow-lg">
      <Card className="max-w-4xl mx-auto">
        <CardContent className="p-6">
          {!showPreferences ? (
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="flex items-start gap-3 flex-1">
                <Shield className="w-6 h-6 text-blue-600 mt-1 flex-shrink-0" />
                <div>
                  <h3 className="font-semibold text-lg mb-2 flex items-center gap-2">
                    Cookie Notice
                    <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded-full">GDPR Compliant</span>
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-300">
                    We use essential cookies for login sessions and security. Analytics cookies help us improve our service. 
                    By continuing, you agree to our Cookie Policy and GDPR-compliant data processing.
                  </p>
                </div>
              </div>
              <div className="flex gap-2 flex-wrap">
                <Button 
                  variant="outline" 
                  onClick={() => setShowPreferences(true)}
                  size="sm"
                  className="flex items-center gap-1"
                >
                  <Settings className="w-4 h-4" />
                  Manage Preferences
                </Button>
                <Button 
                  variant="outline" 
                  onClick={acceptEssential}
                  size="sm"
                  className="flex items-center gap-1"
                >
                  <Shield className="w-4 h-4" />
                  Essential Only
                </Button>
                <Button 
                  onClick={acceptAll}
                  size="sm"
                  className="flex items-center gap-1"
                >
                  <BarChart3 className="w-4 h-4" />
                  Accept All
                </Button>
              </div>
            </div>
          ) : (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold text-lg flex items-center gap-2">
                  <Settings className="w-5 h-5" />
                  Cookie Preferences
                </h3>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowPreferences(false)}
                  className="p-1"
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-start gap-3">
                    <Shield className="w-5 h-5 text-green-600 mt-1" />
                    <div>
                      <h4 className="font-medium flex items-center gap-2">
                        Essential Cookies
                        <span className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded-full">Required</span>
                      </h4>
                      <p className="text-sm text-gray-600 dark:text-gray-300">
                        Required for login sessions, security, and core functionality
                      </p>
                    </div>
                  </div>
                  <input 
                    type="checkbox" 
                    checked={preferences.essential} 
                    disabled 
                    className="w-4 h-4 text-green-600"
                  />
                </div>
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-start gap-3">
                    <BarChart3 className="w-5 h-5 text-blue-600 mt-1" />
                    <div>
                      <h4 className="font-medium">Analytics Cookies</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-300">
                        Help us understand usage patterns and improve our service
                      </p>
                    </div>
                  </div>
                  <input 
                    type="checkbox" 
                    checked={preferences.analytics}
                    onChange={(e) => setPreferences({...preferences, analytics: e.target.checked})}
                    className="w-4 h-4 text-blue-600"
                  />
                </div>
              </div>
              <div className="flex gap-2 mt-6 justify-end">
                <Button 
                  variant="outline" 
                  onClick={() => setShowPreferences(false)}
                  size="sm"
                >
                  Cancel
                </Button>
                <Button 
                  onClick={savePreferences}
                  size="sm"
                  className="flex items-center gap-1"
                >
                  <Shield className="w-4 h-4" />
                  Save Preferences
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}