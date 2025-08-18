import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { AnimatedIcon } from "@/components/ui/animated-icon";
import { CheckCircle, Circle, ArrowRight, ArrowLeft, X, Target, Users, Zap, Calendar, BarChart3, Play, CreditCard, Minimize2, Maximize2 } from "lucide-react";
import { useLocation } from "wouter";

interface WizardStep {
  id: number;
  title: string;
  description: string;
  icon: React.ReactNode;
  content: React.ReactNode;
  actionText: string;
  actionUrl?: string;
  tips: string[];
  route?: string;
}

interface UserStatus {
  userType: 'new' | 'returning';
  hasActiveSubscription: boolean;
  hasBrandSetup: boolean;
  hasConnections: boolean;
  currentUrl: string;
}

export default function OnboardingWizard() {
  const [currentStep, setCurrentStep] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);
  const [isVisible, setIsVisible] = useState(true);
  const [isMinimized, setIsMinimized] = useState(true); // Start minimized
  const [skippedSteps, setSkippedSteps] = useState<number[]>([]);
  const [isSkipped, setIsSkipped] = useState(false);
  const [userStatus, setUserStatus] = useState<UserStatus>({
    userType: 'new',
    hasActiveSubscription: false,
    hasBrandSetup: false,
    hasConnections: false,
    currentUrl: ''
  });
  const [location, setLocation] = useLocation();
  const [isDemoMode, setIsDemoMode] = useState(false);

  // Save progress to localStorage
  const saveProgress = () => {
    const progress = {
      currentStep,
      completedSteps,
      skippedSteps,
      isSkipped,
      isMinimized,
      timestamp: Date.now()
    };
    localStorage.setItem('onboarding-progress', JSON.stringify(progress));
  };

  // Load progress from localStorage
  const loadProgress = () => {
    const saved = localStorage.getItem('onboarding-progress');
    if (saved) {
      const progress = JSON.parse(saved);
      // Only load if saved within last 24 hours
      if (Date.now() - progress.timestamp < 24 * 60 * 60 * 1000) {
        setCurrentStep(progress.currentStep);
        setCompletedSteps(progress.completedSteps);
        setSkippedSteps(progress.skippedSteps || []);
        setIsSkipped(progress.isSkipped || false);
        setIsMinimized(progress.isMinimized !== undefined ? progress.isMinimized : true);
        return true;
      }
    }
    return false;
  };

  // Check user status and detect user type
  useEffect(() => {
    const checkUserStatus = async () => {
      try {
        const response = await fetch('/api/user-status', {
          credentials: 'include'
        });
        
        if (response.ok) {
          const statusData = await response.json();
          const hasActiveSubscription = statusData.hasActiveSubscription || false;
          setUserStatus({
            userType: statusData.userType || 'new',
            hasActiveSubscription,
            hasBrandSetup: statusData.hasBrandSetup || false,
            hasConnections: statusData.hasConnections || false,
            currentUrl: location
          });
          
          // Set mode based on subscription status and current page
          const isDemo = !hasActiveSubscription;
          setIsDemoMode(isDemo);
          
          // Set appropriate starting step based on architecture
          if (!isDemo) {
            // Subscriber flow: different step mapping
            const urlStep = getSubscriberStepFromUrl(location);
            setCurrentStep(urlStep);
          } else {
            // Non-subscriber flow: demo mode steps
            setCurrentStep(0);
          }
        } else {
          // Fallback to /api/user if user-status endpoint doesn't exist
          const fallbackResponse = await fetch('/api/user', {
            credentials: 'include'
          });
          
          if (fallbackResponse.ok) {
            const userData = await fallbackResponse.json();
            const hasActiveSubscription = userData.subscriptionPlan && userData.subscriptionPlan !== 'free';
            setUserStatus({
              userType: hasActiveSubscription ? 'returning' : 'new',
              hasActiveSubscription,
              hasBrandSetup: userData.brandName ? true : false,
              hasConnections: false, // Default to false without specific endpoint
              currentUrl: location
            });
            
            // Set mode based on subscription status
            const isDemo = !hasActiveSubscription;
            setIsDemoMode(isDemo);
            
            // Set appropriate starting step based on architecture
            if (!isDemo) {
              // Subscriber flow: different step mapping
              const urlStep = getSubscriberStepFromUrl(location);
              setCurrentStep(urlStep);
            } else {
              // Non-subscriber flow: demo mode steps
              setCurrentStep(0);
            }
          } else {
            // Default to demo mode for non-authenticated users
            setIsDemoMode(true);
            setCurrentStep(0);
            setUserStatus({
              userType: 'new',
              hasActiveSubscription: false,
              hasBrandSetup: false,
              hasConnections: false,
              currentUrl: location
            });
          }
        }
      } catch (error) {
        console.log('Could not check user status:', error);
        // Default to demo mode on any error
        setIsDemoMode(true);
        setCurrentStep(0);
        setUserStatus({
          userType: 'new',
          hasActiveSubscription: false,
          hasBrandSetup: false,
          hasConnections: false,
          currentUrl: location
        });
      }
    };
    
    checkUserStatus();
  }, [location]);

  // Load progress on mount
  useEffect(() => {
    const hasProgress = loadProgress();
    if (hasProgress) {
      console.log('Onboarding progress restored');
    }
  }, []);

  // Save progress when state changes
  useEffect(() => {
    saveProgress();
  }, [currentStep, completedSteps, skippedSteps, isSkipped]);

  // Demo mode step mapping (non-subscribers)
  const getStepFromUrl = (url: string): number => {
    const urlToStepMap: { [key: string]: number } = {
      '/': 0,
      '/subscription': 1,
      '/brand-purpose': 2,
      '/connect-platforms': 3,
      '/intelligent-schedule': 4,
      '/schedule': 4,
      '/analytics': 5,
      '/video-gen': 4
    };
    return urlToStepMap[url] || currentStep;
  };

  // Subscriber step mapping (different architecture)
  const getSubscriberStepFromUrl = (url: string): number => {
    // Subscriber flow: (1) AI Content → (2) Brand Purpose → (3) Connect Platforms → (4) Analytics
    const urlToStepMap: { [key: string]: number } = {
      '/': 0,
      '/intelligent-schedule': 0, // Main starting point for subscribers
      '/schedule': 0,
      '/video-gen': 0, // Part of content generation
      '/brand-purpose': 1,
      '/connect-platforms': 2,
      '/analytics': 3,
      '/subscription': 1 // Subscription management for existing users
    };
    return urlToStepMap[url] || 0;
  };

  // Update current step based on URL - dynamic highlighting
  useEffect(() => {
    let urlStep: number;
    if (isDemoMode) {
      urlStep = getStepFromUrl(location);
    } else {
      urlStep = getSubscriberStepFromUrl(location);
    }
    
    if (urlStep !== currentStep && !isSkipped) {
      setCurrentStep(urlStep);
    }
  }, [location, isDemoMode, currentStep, isSkipped]);

  // Get page-specific guidance based on architecture and user status
  const getPageGuidance = () => {
    const url = location.split('?')[0];
    
    if (isDemoMode) {
      // Non-subscriber demo guidance
      const guidanceMap: Record<string, string> = {
        '/': 'Welcome to the demo! See how our platform works before subscribing.',
        '/subscription': 'Choose your plan to unlock full features and start automating.',
        '/brand-purpose': 'Preview: Define your brand identity for AI content generation.',
        '/connect-platforms': 'Preview: Connect your social media accounts for publishing.',
        '/intelligent-schedule': 'Preview: Generate and schedule AI-powered content.',
        '/analytics': 'Preview: Monitor your social media performance and growth.'
      };
      return guidanceMap[url] || 'Explore the demo to see how automation transforms your business.';
    }
    
    // Subscriber functional guidance (different architecture)
    const guidanceMap: Record<string, string> = {
      '/': 'Welcome back! Start by generating AI content for your business.',
      '/intelligent-schedule': 'Generate your AI content here, then define your brand purpose.',
      '/schedule': 'Generate your AI content here, then define your brand purpose.',
      '/video-gen': 'Create video content here, then define your brand purpose.',
      '/brand-purpose': 'Define your brand purpose here, then connect your platforms.',
      '/connect-platforms': 'Connect your social media accounts here, then monitor analytics.',
      '/analytics': 'Monitor your performance here and optimise your strategy.',
      '/subscription': 'Manage your subscription and upgrade for more features.'
    };
    
    return guidanceMap[url] || 'Continue your automation workflow using the menu.';
  };

  // Get logical navigation route based on architecture and current step
  const getLogicalNavigation = () => {
    if (isDemoMode) {
      // Demo flow: Welcome → Subscription → Preview pages
      const navigationMap: Record<number, string> = {
        0: '/subscription',
        1: '/brand-purpose', 
        2: '/connect-platforms',
        3: '/intelligent-schedule',
        4: '/analytics',
        5: '/subscription' // Final step leads to subscription
      };
      return navigationMap[currentStep] || '/subscription';
    }
    
    // Subscriber flow: AI Content → Brand Purpose → Connect Platforms → Analytics
    const navigationMap: Record<number, string> = {
      0: '/brand-purpose',  // From AI content to brand purpose
      1: '/connect-platforms', // From brand purpose to connections
      2: '/analytics',      // From connections to analytics
      3: '/intelligent-schedule' // From analytics back to content
    };
    
    return navigationMap[currentStep] || '/intelligent-schedule';
  };

  // Demo mode wizard steps (informational only)
  const demoWizardSteps: WizardStep[] = [
    {
      id: 0,
      title: "Welcome to TheAgencyIQ",
      description: "Preview your AI-powered social media automation platform",
      icon: <AnimatedIcon icon={Zap} colorScheme="gradient" size="sm" />,
      actionText: "Learn More",
      tips: [
        "This is a demo preview of TheAgencyIQ features",
        "Explore each step to understand the platform capabilities"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-6 rounded-lg">
            <h3 className="font-semibold text-lg mb-3">Platform Preview:</h3>
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">AI-powered content generation</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">Multi-platform publishing</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">Queensland business focussed</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">Advanced analytics and insights</span>
              </div>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 1,
      title: "Choose Your Plan",
      description: "Select the subscription that fits your business needs",
      icon: <AnimatedIcon icon={CreditCard} colorScheme="cyan" size="sm" />,
      actionText: "View Plans",
      tips: [
        "Professional plan includes 30 posts per month",
        "All plans include multi-platform publishing"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-4 rounded-lg">
            <h4 className="font-medium text-gray-800 mb-2">Plan Options:</h4>
            <div className="space-y-3">
              <div className="bg-white p-4 rounded-lg">
                <h4 className="font-medium text-gray-800 mb-2">Professional Plan</h4>
                <p className="text-2xl font-bold text-gray-600">$99.99</p>
                <div className="text-sm text-gray-600 space-y-1">
                  <div>30 posts per month</div>
                  <div>5 platforms</div>
                  <div>Premium analytics</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 2,
      title: "Brand Purpose Setup",
      description: "Define your brand identity for personalized content",
      icon: <AnimatedIcon icon={Target} colorScheme="blue" size="sm" />,
      actionText: "Setup Brand",
      tips: [
        "Brand purpose drives AI content generation",
        "Setup takes about 5 minutes"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-4 rounded-lg">
            <h4 className="font-medium text-gray-800 mb-2">Brand Setup Preview:</h4>
            <p className="text-sm text-gray-600">
              Define your business purpose, target audience, and core messaging to generate personalized content that resonates with your Queensland customers.
            </p>
          </div>
        </div>
      )
    },
    {
      id: 3,
      title: "Connect Platforms",
      description: "Link your social media accounts for publishing",
      icon: <AnimatedIcon icon={Users} colorScheme="pink" size="sm" />,
      actionText: "Connect",
      tips: [
        "Connect Facebook, Instagram, LinkedIn, YouTube, and X",
        "OAuth secure authentication"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-4 rounded-lg">
            <h4 className="font-medium text-gray-800 mb-2">Platform Integration:</h4>
            <p className="text-sm text-gray-600">
              Securely connect your social media accounts to enable automatic posting across all major platforms.
            </p>
          </div>
        </div>
      )
    },
    {
      id: 4,
      title: "AI Content Generation",
      description: "Generate and schedule your social media content",
      icon: <Zap className="w-4 h-4" />,
      actionText: "Generate",
      tips: [
        "AI creates Queensland-focussed content",
        "Includes video generation capabilities"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-4 rounded-lg">
            <h4 className="font-medium text-gray-800 mb-2">AI Content Preview:</h4>
            <p className="text-sm text-gray-600">
              Advanced AI generates engaging content tailored to Queensland markets with automatic scheduling and video creation.
            </p>
          </div>
        </div>
      )
    },
    {
      id: 5,
      title: "Subscribe Now",
      description: "Unlock the full power of AI social media automation",
      icon: <BarChart3 className="w-4 h-4" />,
      actionText: "Subscribe Now",
      tips: [
        "Ready to transform your social media presence?",
        "Start your 30-day content cycle today"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-6 rounded-lg">
            <h3 className="font-semibold text-lg mb-3">Ready to Get Started?</h3>
            <p className="text-sm text-gray-600 mb-4">
              Subscribe now to unlock the full power of AI-driven social media automation for your Queensland business.
            </p>
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">30 AI-generated posts monthly</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">Multi-platform publishing</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">Queensland business focus</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">Advanced analytics dashboard</span>
              </div>
            </div>
          </div>
        </div>
      )
    }
  ];

  // Functional mode wizard steps (subscriber architecture)
  const functionalWizardSteps: WizardStep[] = [
    {
      id: 0,
      title: "Generate smart content",
      description: "Start by creating your social media posts",
      icon: <Zap className="w-4 h-4" />,
      actionText: "Generate",
      route: "/intelligent-schedule",
      tips: [
        "This is where subscribers start their workflow",
        "Generate content first, then set up brand purpose"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-6 rounded-lg">
            <h3 className="font-semibold text-lg mb-3">AI Content Generation:</h3>
            <p className="text-sm text-gray-600 mb-4">
              Start here! Generate engaging content tailored to Queensland markets with automatic scheduling and video creation.
            </p>
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">Active subscription confirmed</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">AI content generation enabled</span>
              </div>
              <div className="flex items-center space-x-2">
                <CheckCircle className="w-4 h-4 text-green-500" />
                <span className="text-sm">Multi-platform publishing ready</span>
              </div>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 1,
      title: "Define Brand Purpose",
      description: "Set up your brand identity for personalized content",
      icon: <Target className="w-4 h-4" />,
      actionText: "Setup Brand",
      route: "/brand-purpose",
      tips: [
        "Complete brand setup to unlock AI generation",
        "Takes about 5 minutes to complete"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-4 rounded-lg">
            <h4 className="font-medium text-gray-800 mb-2">Brand Purpose Setup:</h4>
            <p className="text-sm text-gray-600">
              {userStatus.hasBrandSetup ? 
                "Your brand purpose is configured. You can update it anytime." :
                "Define your business purpose and target audience to generate personalized content."
              }
            </p>
          </div>
        </div>
      )
    },
    {
      id: 2,
      title: "Connect Platforms",
      description: "Link your social media accounts for publishing",
      icon: <Users className="w-4 h-4" />,
      actionText: "Connect",
      route: "/connect-platforms",
      tips: [
        "Connect all platforms for maximum reach",
        "OAuth authentication ensures security"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-4 rounded-lg">
            <h4 className="font-medium text-gray-800 mb-2">Platform Connections:</h4>
            <p className="text-sm text-gray-600">
              {userStatus.hasConnections ? 
                "Platform connections are active. Check status regularly." :
                "Connect your social media accounts to enable automatic posting."
              }
            </p>
          </div>
        </div>
      )
    },
    {
      id: 3,
      title: "Monitor Performance",
      description: "Track analytics and optimise your strategy",
      icon: <BarChart3 className="w-4 h-4" />,
      actionText: "View Analytics",
      route: "/analytics",
      tips: [
        "Monitor engagement across all platforms",
        "Use insights to optimise content strategy"
      ],
      content: (
        <div className="space-y-4">
          <div className="bg-white border border-gray-200 p-4 rounded-lg">
            <h4 className="font-medium text-gray-800 mb-2">Analytics Dashboard:</h4>
            <p className="text-sm text-gray-600">
              Track performance metrics and get actionable insights to improve your social media strategy.
            </p>
          </div>
        </div>
      )
    }
  ];

  // Select appropriate wizard steps based on mode
  const wizardSteps = isDemoMode ? demoWizardSteps : functionalWizardSteps;

  // Navigation functions for different modes
  const handleNext = () => {
    if (isDemoMode) {
      // Demo mode: just advance to next step
      if (currentStep < wizardSteps.length - 1) {
        setCurrentStep(currentStep + 1);
      }
    } else {
      // Functional mode: navigate to logical route
      const nextRoute = getLogicalNavigation();
      if (nextRoute) {
        setLocation(nextRoute);
      }
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleActionClick = () => {
    if (isDemoMode) {
      // Demo mode: last step goes to subscription
      if (currentStep === wizardSteps.length - 1) {
        setLocation('/subscription');
      } else {
        handleNext();
      }
    } else {
      // Functional mode: navigate to route or next step
      handleNext();
    }
  };

  // Get current step data
  const currentWizardStep = wizardSteps[currentStep];

  // Handle minimization
  const handleMinimize = () => {
    setIsMinimized(!isMinimized);
    saveProgress();
  };

  // Handle skip functionality
  const handleSkip = () => {
    setIsSkipped(true);
    setIsVisible(false);
  };

  // Handle resume functionality
  const handleResume = () => {
    setIsSkipped(false);
    setIsVisible(true);
  };

  // Skip floating button
  const FloatingResumeButton = () => (
    <div className="fixed bottom-2 right-2 sm:bottom-4 sm:right-4 z-50">
      <Button
        onClick={handleResume}
        className="bg-blue-500 hover:bg-blue-600 text-white shadow-lg text-xs sm:text-sm px-2 sm:px-4"
        size="sm"
      >
        <span className="hidden sm:inline">Resume Guide</span>
        <span className="sm:hidden">Resume</span>
      </Button>
    </div>
  );

  if (isSkipped) {
    return <FloatingResumeButton />;
  }

  if (!isVisible) return null;

  return (
    <div className="fixed bottom-2 right-2 sm:bottom-4 sm:right-4 z-50 w-[calc(100vw-1rem)] sm:w-96 max-w-[calc(100vw-1rem)] wizard-mobile-optimized">
      <Card className="bg-white border-gray-200 shadow-lg">
        <CardHeader 
          className="pb-2 sm:pb-3 wizard-header-mobile"
        >
          <div className="flex items-center justify-between">
            <div 
              className={`flex items-center space-x-1 sm:space-x-2 min-w-0 flex-1 ${isMinimized ? 'cursor-pointer hover:bg-gray-50 rounded-md p-1 -m-1' : ''}`}
              onClick={isMinimized ? handleMinimize : undefined}
            >
              <div className="flex items-center min-w-0 flex-1">
                {isDemoMode && !isMinimized && (
                  <Badge variant="secondary" className="mr-1 sm:mr-2 text-xs shrink-0">
                    Learn more
                  </Badge>
                )}
                <div className="w-2 h-2 bg-blue-500 rounded-full mr-1 sm:mr-2 shrink-0"></div>
                <CardTitle className="text-xs sm:text-sm lg:text-base font-semibold text-muted-foreground truncate">
                  {isMinimized ? "Your little helper" : currentWizardStep?.title}
                </CardTitle>
                {isMinimized && (
                  <div className="ml-2 text-xs text-gray-400 hidden sm:inline">
                    Step {currentStep + 1}/{wizardSteps.length}
                  </div>
                )}
              </div>
            </div>
            <Button
              onClick={handleMinimize}
              variant="ghost"
              size="sm"
              className="text-gray-500 hover:text-gray-700 shrink-0 ml-2 p-1"
              title={isMinimized ? "Expand guide" : "Minimize guide"}
            >
              {isMinimized ? <Maximize2 className="w-3 h-3 sm:w-4 sm:h-4" /> : <Minimize2 className="w-3 h-3 sm:w-4 sm:h-4" />}
            </Button>
          </div>
          {!isMinimized && (
            <div className="mt-2 sm:mt-3">
              <p className="text-xs sm:text-sm text-gray-600 mb-2">
                {currentWizardStep?.description}
              </p>
              <div className="bg-blue-50 border border-blue-200 p-2 rounded-md">
                <p className="text-xs sm:text-sm text-blue-800">
                  {getPageGuidance()}
                </p>
              </div>
              <div className="flex items-center space-x-2 mb-2 sm:mb-3">
                <Progress 
                  value={((currentStep + 1) / wizardSteps.length) * 100} 
                  className="flex-1 h-2"
                />
                <span className="text-xs text-gray-500 shrink-0">
                  {currentStep + 1} / {wizardSteps.length}
                </span>
              </div>
            </div>
          )}
        </CardHeader>
        
        {!isMinimized && (
          <CardContent className="pt-0 px-3 sm:px-6">
            <div className="space-y-3 sm:space-y-4">
              <div className="text-xs sm:text-sm leading-relaxed">
                {currentWizardStep?.content}
              </div>
              
              {/* Tips section for better mobile UX */}
              {currentWizardStep?.tips && currentWizardStep.tips.length > 0 && (
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                  <div className="space-y-1">
                    {currentWizardStep.tips.map((tip, index) => (
                      <div key={index} className="flex items-start space-x-2">
                        <div className="w-1 h-1 bg-blue-500 rounded-full mt-2 shrink-0"></div>
                        <p className="text-xs sm:text-sm text-blue-700">{tip}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              <div className="flex items-center justify-between pt-3 sm:pt-4 gap-3">
                <Button
                  onClick={handlePrevious}
                  disabled={currentStep === 0}
                  variant="outline"
                  size="sm"
                  className="flex items-center space-x-1 text-xs sm:text-sm px-3 sm:px-4 py-2 min-h-[36px] touch-manipulation"
                >
                  <ArrowLeft className="w-3 h-3 sm:w-4 sm:h-4" />
                  <span className="hidden sm:inline">Previous</span>
                  <span className="sm:hidden">Prev</span>
                </Button>
                
                <div className="flex space-x-2">
                  <Button
                    onClick={handleSkip}
                    variant="ghost"
                    size="sm"
                    className="text-xs sm:text-sm text-gray-500 hover:text-gray-700 px-2 sm:px-3 py-2 min-h-[36px] touch-manipulation"
                  >
                    Skip
                  </Button>
                  
                  {currentStep === wizardSteps.length - 1 ? (
                    <Button
                      onClick={handleActionClick}
                      className={`${
                        isDemoMode 
                          ? 'bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700' 
                          : 'bg-blue-500 hover:bg-blue-600'
                      } text-white text-xs sm:text-sm px-3 sm:px-4 py-2 min-h-[36px] touch-manipulation`}
                      size="sm"
                    >
                      {isDemoMode ? (
                        <>
                          <span className="hidden sm:inline">Subscribe Now</span>
                          <span className="sm:hidden">Subscribe</span>
                        </>
                      ) : (
                        'Complete'
                      )}
                    </Button>
                  ) : (
                    <Button
                      onClick={handleNext}
                      className="bg-blue-500 hover:bg-blue-600 text-white text-xs sm:text-sm px-3 sm:px-4 py-2 min-h-[36px] touch-manipulation flex items-center space-x-1"
                      size="sm"
                    >
                      <span>Next</span>
                      <ArrowRight className="w-3 h-3 sm:w-4 sm:h-4" />
                    </Button>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        )}
      </Card>
    </div>
  );
};
