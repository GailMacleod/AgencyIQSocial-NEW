import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Menu, X, Home, Calendar, BarChart3, Settings, User, Plus, Zap } from "lucide-react";
import { useLocation } from "wouter";
import { Badge } from "@/components/ui/badge";
import { useQuery } from "@tanstack/react-query";
import { useSubscriptionSSE } from "@/hooks/useSubscriptionSSE";

interface NavigationItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  path: string;
  badge?: string;
  color?: string;
}

export function MobileNavigationMenu() {
  const [isOpen, setIsOpen] = useState(false);
  const [location, setLocation] = useLocation();

  const { data: quotaData } = useQuery({
    queryKey: ['/api/subscription-usage'],
    enabled: true
  }) as { data?: { remainingPosts?: number; subscriptionPlan?: string; publishedPosts?: number } };

  // Real-time subscription status updates
  const { status: sseStatus } = useSubscriptionSSE();

  const navigationItems: NavigationItem[] = [
    {
      id: 'home',
      label: 'Dashboard',
      icon: Home,
      path: '/',
      color: 'text-purple-600'
    },
    {
      id: 'generate',
      label: 'Generate Content',
      icon: Plus,
      path: '/intelligent-schedule',
      color: 'text-purple-600',
      badge: (sseStatus?.remainingPosts || quotaData?.remainingPosts || 0) > 0 
        ? `${sseStatus?.remainingPosts || quotaData?.remainingPosts || 0} left` 
        : 'Limit reached'
    },
    {
      id: 'schedule',
      label: 'Manage Posts',
      icon: Calendar,
      path: '/schedule',
      color: 'text-green-600'
    },
    {
      id: 'analytics',
      label: 'Analytics',
      icon: BarChart3,
      path: '/yearly-analytics',
      color: 'text-blue-600'
    },
    {
      id: 'platforms',
      label: 'Platform Setup',
      icon: Settings,
      path: '/token-status',
      color: 'text-orange-600'
    },
    {
      id: 'subscription',
      label: 'Subscription',
      icon: Zap,
      path: '/subscription',
      color: 'text-yellow-600'
    },
    {
      id: 'profile',
      label: 'Profile',
      icon: User,
      path: '/profile',
      color: 'text-gray-600'
    }
  ];

  const handleNavigation = (path: string) => {
    setLocation(path);
    setIsOpen(false);
  };

  return (
    <Sheet open={isOpen} onOpenChange={setIsOpen}>
      <SheetTrigger asChild>
        <Button variant="ghost" size="sm" className="md:hidden" aria-label="Open navigation menu">
          <Menu className="w-5 h-5" />
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="w-80">
        <SheetHeader>
          <SheetTitle className="text-left">TheAgencyIQ</SheetTitle>
        </SheetHeader>
        
        <div className="mt-6 space-y-1">
          {navigationItems.map((item) => {
            const isActive = location === item.path;
            const IconComponent = item.icon;
            
            return (
              <Button
                key={item.id}
                variant={isActive ? "secondary" : "ghost"}
                className={`w-full justify-start h-12 px-4 ${
                  isActive ? 'bg-purple-50 border-l-4 border-purple-600' : ''
                }`}
                onClick={() => handleNavigation(item.path)}
              >
                <div className="flex items-center justify-between w-full">
                  <div className="flex items-center space-x-3">
                    <IconComponent className={`w-5 h-5 ${item.color}`} />
                    <span className="font-medium">{item.label}</span>
                  </div>
                  {item.badge && (
                    <Badge 
                      variant="outline" 
                      className={`text-xs ${
                        item.badge.includes('reached') ? 'bg-red-50 text-red-700' : 'bg-green-50 text-green-700'
                      }`}
                    >
                      {item.badge}
                    </Badge>
                  )}
                </div>
              </Button>
            );
          })}
        </div>

        {/* Quick Stats */}
        <div className="mt-8 p-4 bg-gray-50 rounded-lg">
          <h3 className="font-medium text-sm text-gray-900 mb-2">Quick Stats</h3>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Posts Remaining</span>
              <span className="font-medium">
                {sseStatus?.remainingPosts || quotaData?.remainingPosts || 0} / {sseStatus?.totalPosts || 
                  (quotaData?.subscriptionPlan === 'professional' ? 30 :
                  quotaData?.subscriptionPlan === 'growth' ? 20 :
                  quotaData?.subscriptionPlan === 'starter' ? 10 : 30)
                }
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Plan</span>
              <span className="font-medium capitalize">{sseStatus?.plan || quotaData?.subscriptionPlan || 'Professional'}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Published</span>
              <span className="font-medium">{(sseStatus?.totalPosts || 0) - (sseStatus?.remainingPosts || 0) || quotaData?.publishedPosts || 0}</span>
            </div>
          </div>
        </div>

        <div className="mt-6 pt-4 border-t">
          <Button 
            variant="outline" 
            className="w-full"
            onClick={() => setIsOpen(false)}
          >
            <X className="w-4 h-4 mr-2" />
            Close Menu
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

// Swipe gesture hook for mobile post navigation
export function useSwipeGesture(onSwipeLeft?: () => void, onSwipeRight?: () => void) {
  const [touchStart, setTouchStart] = useState<number | null>(null);
  const [touchEnd, setTouchEnd] = useState<number | null>(null);

  const minSwipeDistance = 50;

  const onTouchStart = (e: React.TouchEvent) => {
    setTouchEnd(null);
    setTouchStart(e.targetTouches[0].clientX);
  };

  const onTouchMove = (e: React.TouchEvent) => {
    setTouchEnd(e.targetTouches[0].clientX);
  };

  const onTouchEnd = () => {
    if (!touchStart || !touchEnd) return;
    
    const distance = touchStart - touchEnd;
    const isLeftSwipe = distance > minSwipeDistance;
    const isRightSwipe = distance < -minSwipeDistance;

    if (isLeftSwipe && onSwipeLeft) {
      onSwipeLeft();
    }
    if (isRightSwipe && onSwipeRight) {
      onSwipeRight();
    }
  };

  return {
    onTouchStart,
    onTouchMove,
    onTouchEnd
  };
}