import { useState } from "react";
import { Link, useLocation } from "wouter";
import { Menu, User, LogOut, CreditCard, Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import { MobileNavigationMenu } from "./navigation/MobileNavigationMenu";
import { QuickTooltip } from "./navigation/ContextualTooltip";

interface HeaderProps {
  showBack?: string;
  showLogin?: boolean;
  showUserMenu?: boolean;
  title?: string;
}

interface User {
  id: number;
  email: string;
  phone: string;
  subscriptionPlan: string;
  remainingPosts: number;
  totalPosts: number;
}

export default function Header({ 
  showBack, 
  showLogin, 
  showUserMenu,
  title
}: HeaderProps) {
  const { toast } = useToast();
  const [, setLocation] = useLocation();

  // Fetch user data for authenticated users
  const { data: user } = useQuery<User>({
    queryKey: ["/api/user"],
    enabled: showUserMenu,
  });

  const handleLogout = async () => {
    try {
      await apiRequest("POST", "/api/auth/logout", {});
      
      // Clear all cached data immediately
      localStorage.clear();
      sessionStorage.clear();
      
      // Clear any cached data
      if ('caches' in window) {
        caches.keys().then(names => {
          names.forEach(name => {
            caches.delete(name);
          });
        });
      }
      
      // Clear specific application data
      localStorage.removeItem('onboarding-progress');
      localStorage.removeItem('wizardProgress');
      localStorage.removeItem('userPreferences');
      
      console.log('Complete session cleanup on logout');
      
      toast({
        title: "Logged Out",
        description: "You have been logged out successfully",
      });
      
      // Force page reload to ensure complete session cleanup
      window.location.replace("/");
    } catch (error: any) {
      console.error("Logout error:", error);
      
      // Force logout even on error
      localStorage.clear();
      sessionStorage.clear();
      window.location.replace("/");
      
      toast({
        title: "Logout Failed",
        description: error.message || "Failed to log out",
        variant: "destructive",
      });
    }
  };

  const handleCancelSubscription = () => {
    toast({
      title: "Cancel Subscription",
      description: "Contact support to cancel your subscription",
    });
  };

  // Landing page header (simple with Sign In and Get Started)
  if (showLogin) {
    return (
      <nav className="sticky top-0 z-50 bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <MobileNavigationMenu />
              <Link href="/" className="flex items-center">
                <img 
                  src="/logo.png" 
                  alt="TheAgencyIQ" 
                  className="h-8 w-auto cursor-pointer hover:opacity-80 transition-opacity"
                  onError={(e) => {
                    console.error('Logo failed to load from /logo.png');
                    // Fallback to text if logo fails to load
                    const img = e.target as HTMLImageElement;
                    img.style.display = 'none';
                    const parent = img.parentElement;
                    if (parent) {
                      parent.innerHTML = '<span class="text-xl font-bold text-blue-600">TheAgencyIQ</span>';
                    }
                  }}
                />
              </Link>
            </div>
            
            <div className="flex items-center space-x-2">
              <Button variant="ghost" className="text-gray-700 hover:text-gray-900">
                Sign In
              </Button>
              <Button 
                className="bg-blue-600 hover:bg-blue-700 text-white px-6"
                style={{ backgroundColor: '#3250fa' }}
              >
                Get Started
              </Button>
            </div>
          </div>
        </div>
      </nav>
    );
  }

  // Authenticated pages header (logo left, hamburger right)
  return (
    <nav className="sticky top-0 z-50 bg-white border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <Link href="/schedule" className="flex items-center">
            <img 
              src="/logo.png" 
              alt="TheAgencyIQ" 
              className="h-8 w-auto cursor-pointer hover:opacity-80 transition-opacity"
              onError={(e) => {
                console.error('Logo failed to load from /logo.png');
                // Fallback to text if logo fails to load
                const img = e.target as HTMLImageElement;
                img.style.display = 'none';
                const parent = img.parentElement;
                if (parent) {
                  parent.innerHTML = '<span class="text-xl font-bold text-blue-600">TheAgencyIQ</span>';
                }
              }}
            />
          </Link>
          
          {showUserMenu && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="p-2">
                  <Menu className="h-5 w-5 text-gray-600" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-64">
                {user ? (
                  <DropdownMenuItem className="flex flex-col items-start p-4 cursor-default">
                    <div className="font-medium text-gray-900">{user.email}</div>
                    <div className="text-sm text-gray-500 capitalize">{user.subscriptionPlan} Plan</div>
                    <div className="text-xs text-gray-400 mt-1">
                      {user.remainingPosts} of {user.totalPosts} posts remaining
                    </div>
                  </DropdownMenuItem>
                ) : (
                  <DropdownMenuItem className="flex flex-col items-start p-4 cursor-default">
                    <div className="font-medium text-gray-900">Loading...</div>
                  </DropdownMenuItem>
                )}
                
                <DropdownMenuSeparator />
                
                <DropdownMenuItem asChild>
                  <Link href="/schedule" className="w-full cursor-pointer">
                    <Settings className="h-4 w-4 mr-2" />
                    Content Calendar
                  </Link>
                </DropdownMenuItem>
                
                <DropdownMenuItem asChild>
                  <Link href="/brand-purpose" className="w-full cursor-pointer">
                    <User className="h-4 w-4 mr-2" />
                    Brand Purpose
                  </Link>
                </DropdownMenuItem>
                
                <DropdownMenuSeparator />
                
                {/* Only show Cancel Subscription if subscription is active */}
                {(user as any)?.subscriptionActive && user?.subscriptionPlan !== 'cancelled' && (
                  <DropdownMenuItem onClick={handleCancelSubscription} className="cursor-pointer">
                    <CreditCard className="h-4 w-4 mr-2" />
                    Cancel Subscription
                  </DropdownMenuItem>
                )}
                
                <DropdownMenuItem onClick={handleLogout} className="text-red-600 cursor-pointer">
                  <LogOut className="h-4 w-4 mr-2" />
                  Sign Out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>
    </nav>
  );
}
