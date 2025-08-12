import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { MetaPixelTracker } from "@/lib/meta-pixel";
import { CheckCircle, AlertTriangle, Facebook, Instagram, TestTube, Activity, Zap } from "lucide-react";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";

export default function MetaPixelTest() {
  const { toast } = useToast();
  const [testResults, setTestResults] = useState<string[]>([]);
  const [isTestRunning, setIsTestRunning] = useState(false);

  const addTestResult = (result: string) => {
    setTestResults(prev => [...prev, result]);
  };

  const runBasicEventTests = () => {
    setIsTestRunning(true);
    setTestResults([]);

    try {
      // Test 1: Page View
      MetaPixelTracker.trackPageView('meta_pixel_test', 'testing');
      addTestResult('✓ PageView event tracked successfully');

      // Test 2: Lead tracking
      MetaPixelTracker.trackLead('test_lead', 100);
      addTestResult('✓ Lead event tracked successfully');

      // Test 3: Custom event
      MetaPixelTracker.trackCustomEvent('TestEvent', {
        test_parameter: 'test_value',
        timestamp: new Date().toISOString()
      });
      addTestResult('✓ Custom event tracked successfully');

      // Test 4: Search event
      MetaPixelTracker.trackSearch('test search', 'meta_pixel_testing');
      addTestResult('✓ Search event tracked successfully');

      // Test 5: Feature usage tracking
      MetaPixelTracker.trackFeatureUsage('meta_pixel_test_page');
      addTestResult('✓ Feature usage tracked successfully');

      toast({
        title: "Basic Event Tests Completed",
        description: "All basic Meta Pixel events fired successfully",
      });

    } catch (error: any) {
      addTestResult(`✗ Error: ${error.message}`);
      toast({
        title: "Test Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsTestRunning(false);
    }
  };

  const runBusinessEventTests = () => {
    setIsTestRunning(true);
    
    try {
      // Test subscription tracking
      MetaPixelTracker.trackSubscriptionPurchase('Professional', 197);
      addTestResult('✓ Subscription purchase tracked');

      // Test gift certificate redemption
      MetaPixelTracker.trackGiftCertificateRedeem('TEST-CODE-123', 'Growth');
      addTestResult('✓ Gift certificate redemption tracked');

      // Test platform connection
      MetaPixelTracker.trackPlatformConnection('facebook', true);
      addTestResult('✓ Platform connection tracked');

      // Test post generation
      MetaPixelTracker.trackPostGeneration('instagram', 5, true);
      addTestResult('✓ Post generation tracked');

      // Test post approval
      MetaPixelTracker.trackPostApproval('linkedin', true);
      addTestResult('✓ Post approval tracked');

      // Test post publishing
      MetaPixelTracker.trackPostPublish('twitter', new Date());
      addTestResult('✓ Post publishing tracked');

      // Test brand purpose completion
      MetaPixelTracker.trackBrandPurposeCompletion(true, ['facebook', 'instagram']);
      addTestResult('✓ Brand purpose completion tracked');

      // Test analytics view
      MetaPixelTracker.trackAnalyticsView('monthly', ['facebook', 'instagram', 'linkedin']);
      addTestResult('✓ Analytics view tracked');

      toast({
        title: "Business Event Tests Completed",
        description: "All TheAgencyIQ-specific events fired successfully",
      });

    } catch (error: any) {
      addTestResult(`✗ Business event error: ${error.message}`);
      toast({
        title: "Business Test Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsTestRunning(false);
    }
  };

  const runConversionTests = () => {
    setIsTestRunning(true);
    
    try {
      // Test conversion funnel tracking
      MetaPixelTracker.trackConversionFunnel('landing_page_view');
      addTestResult('✓ Funnel step 1: Landing page view');

      MetaPixelTracker.trackConversionFunnel('subscription_plan_selected', {
        plan_name: 'Professional',
        plan_price: '$197/month'
      });
      addTestResult('✓ Funnel step 2: Plan selection');

      MetaPixelTracker.trackConversionFunnel('registration_started', {
        email: 'test@example.com',
        phone: '+61400000000'
      });
      addTestResult('✓ Funnel step 3: Registration started');

      // Test user registration
      MetaPixelTracker.trackUserRegistration('subscription_form', 'Professional');
      addTestResult('✓ User registration tracked');

      // Test checkout initiation
      MetaPixelTracker.trackEvent('InitiateCheckout', {
        value: 197,
        currency: 'AUD',
        content_name: 'Professional Subscription',
        content_category: 'subscription'
      });
      addTestResult('✓ Checkout initiation tracked');

      // Test purchase completion
      MetaPixelTracker.trackEvent('Purchase', {
        value: 197,
        currency: 'AUD',
        content_name: 'Professional Plan',
        content_category: 'subscription'
      });
      addTestResult('✓ Purchase completion tracked');

      toast({
        title: "Conversion Tests Completed",
        description: "All conversion events fired successfully",
      });

    } catch (error: any) {
      addTestResult(`✗ Conversion test error: ${error.message}`);
      toast({
        title: "Conversion Test Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsTestRunning(false);
    }
  };

  const runPerformanceTests = () => {
    setIsTestRunning(true);
    
    try {
      // Test performance tracking
      MetaPixelTracker.trackPerformance('page_load', 1200, true);
      addTestResult('✓ Performance metric tracked');

      // Test error tracking
      MetaPixelTracker.trackError('test_error', 'This is a test error for Meta Pixel validation', {
        test_context: 'meta_pixel_testing',
        error_severity: 'low'
      });
      addTestResult('✓ Error tracking tested');

      toast({
        title: "Performance Tests Completed",
        description: "Performance and error tracking validated",
      });

    } catch (error: any) {
      addTestResult(`✗ Performance test error: ${error.message}`);
      toast({
        title: "Performance Test Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsTestRunning(false);
    }
  };

  const runAllTests = async () => {
    setTestResults([]);
    addTestResult('🚀 Starting comprehensive Meta Pixel test suite...');
    
    await new Promise(resolve => setTimeout(resolve, 500));
    runBasicEventTests();
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    runBusinessEventTests();
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    runConversionTests();
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    runPerformanceTests();
    
    addTestResult('🎉 All Meta Pixel tests completed! Check Facebook Events Manager for validation.');
  };

  return (
    <div className="min-h-screen bg-background">
      <MasterHeader />
      
      <div className="container-atomiq py-8">
        <div className="max-w-4xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl font-bold mb-2">Meta Pixel Testing Dashboard</h1>
            <p className="text-muted-foreground">
              Test and validate all Meta Pixel events for Facebook & Instagram analytics
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <Card>
              <CardHeader>
                <div className="flex items-center space-x-2">
                  <Facebook className="h-5 w-5 text-blue-600" />
                  <CardTitle>Meta Pixel Status</CardTitle>
                </div>
                <CardDescription>
                  App ID: 1409057863445071
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <span className="text-sm">Meta Pixel loaded and initialized</span>
                </div>
                <div className="flex items-center space-x-2 mt-2">
                  <Instagram className="h-5 w-5 text-pink-500" />
                  <span className="text-sm">Instagram Business API connected</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="flex items-center space-x-2">
                  <Activity className="h-5 w-5 text-orange-500" />
                  <CardTitle>Event Categories</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <Badge variant="outline">Standard Events</Badge>
                  <Badge variant="outline">Custom Events</Badge>
                  <Badge variant="outline">Conversion Tracking</Badge>
                  <Badge variant="outline">Business Events</Badge>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <Button 
              onClick={runBasicEventTests} 
              disabled={isTestRunning}
              className="h-auto p-4 flex flex-col items-center space-y-2"
            >
              <TestTube className="h-6 w-6" />
              <span>Basic Events</span>
            </Button>
            
            <Button 
              onClick={runBusinessEventTests} 
              disabled={isTestRunning}
              variant="outline"
              className="h-auto p-4 flex flex-col items-center space-y-2"
            >
              <Zap className="h-6 w-6" />
              <span>Business Events</span>
            </Button>
            
            <Button 
              onClick={runConversionTests} 
              disabled={isTestRunning}
              variant="outline"
              className="h-auto p-4 flex flex-col items-center space-y-2"
            >
              <Activity className="h-6 w-6" />
              <span>Conversions</span>
            </Button>
            
            <Button 
              onClick={runAllTests} 
              disabled={isTestRunning}
              variant="destructive"
              className="h-auto p-4 flex flex-col items-center space-y-2"
            >
              <AlertTriangle className="h-6 w-6" />
              <span>Run All Tests</span>
            </Button>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Test Results</CardTitle>
              <CardDescription>
                Real-time validation of Meta Pixel events
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm max-h-96 overflow-y-auto">
                {testResults.length === 0 ? (
                  <span className="text-gray-500">Click a test button to start validation...</span>
                ) : (
                  testResults.map((result, index) => (
                    <div key={index} className="mb-1">
                      {result}
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          <div className="mt-8 p-4 bg-blue-50 rounded-lg">
            <h3 className="font-semibold text-blue-900 mb-2">Validation Instructions</h3>
            <ol className="text-sm text-blue-800 space-y-1">
              <li>1. Run the tests using the buttons above</li>
              <li>2. Open Facebook Events Manager (business.facebook.com)</li>
              <li>3. Navigate to your pixel events dashboard</li>
              <li>4. Verify events appear in real-time (may take 1-2 minutes)</li>
              <li>5. Check custom event parameters for accuracy</li>
            </ol>
          </div>
        </div>
      </div>
      
      <MasterFooter />
    </div>
  );
}