import { useState, useEffect } from "react";
import { Menu, X, User, CreditCard, LogOut, Building2, Calendar, Share2, BarChart3, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";

interface User {
  id: number;
  email: string;
  phone: string;
  subscriptionPlan: string;
  remainingPosts: number;
  totalPosts: number;
}

export default function UserMenu() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: user } = useQuery<User>({
    queryKey: ["/api/user"],
    retry: false,
  });

  const logoutMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/auth/logout"),
    onSuccess: (data: any) => {
      // Clear all cached data immediately
      queryClient.clear();
      queryClient.invalidateQueries();
      
      // Clear localStorage and sessionStorage completely
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
      
      // Force page reload to ensure complete session cleanup
      window.location.replace("/");
    },
    onError: (error: any) => {
      console.error("Logout error:", error);
      
      // Force logout even on error
      localStorage.clear();
      sessionStorage.clear();
      window.location.replace("/");
      
      // Even on error, force logout locally
      queryClient.clear();
      localStorage.clear();
      sessionStorage.clear();
      
      toast({
        title: "Logged Out",
        description: "Session cleared. Redirecting to home page.",
      });
      
      setTimeout(() => {
        window.location.href = "/";
      }, 1000);
    },
  });

  const cancelSubscriptionMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/cancel-subscription"),
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/user"] });
      queryClient.invalidateQueries({ queryKey: ["/api/platform-connections"] });
      
      const summary = data.summary;
      
      toast({
        title: "Subscription Cancelled",
        description: `Your subscription has been cancelled successfully. ${summary?.platformConnectionsRevoked || 0} platform connections revoked, ${summary?.postsDeleted || 0} posts deleted.`,
        duration: 8000,
      });
      
      console.log("Subscription cancellation summary:", summary);
    },
    onError: (error: any) => {
      console.error("Cancel subscription error:", error);
      toast({
        title: "Error",
        description: error.response?.data?.message || "Failed to cancel subscription. Please contact support.",
        variant: "destructive",
        duration: 8000,
      });
    },
  });

  const deleteFacebookMutation = useMutation({
    mutationFn: () => apiRequest("DELETE", "/api/platform-connections/facebook"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/platform-connections"] });
      toast({
        title: "Facebook Data Deleted",
        description: "All Facebook data and connections have been removed from your account.",
      });
    },
    onError: (error: any) => {
      console.error("Delete Facebook data error:", error);
      toast({
        title: "Error",
        description: "Failed to delete Facebook data. Please try again.",
        variant: "destructive",
      });
    },
  });

  const deleteInstagramMutation = useMutation({
    mutationFn: () => apiRequest("DELETE", "/api/platform-connections/instagram"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/platform-connections"] });
      toast({
        title: "Instagram Data Deleted",
        description: "All Instagram data and connections have been removed from your account.",
      });
    },
    onError: (error: any) => {
      console.error("Delete Instagram data error:", error);
      toast({
        title: "Error",
        description: "Failed to delete Instagram data. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleCancelSubscription = () => {
    const confirmMessage = `⚠️ PERMANENT SUBSCRIPTION CANCELLATION

This will immediately:
• Cancel your subscription and billing
• Close ALL platform connections (Facebook, Instagram, LinkedIn, X, YouTube)
• Delete ALL your posts and content
• Remove ALL your brand purpose data
• Revoke ALL OAuth tokens from connected platforms

This action CANNOT be undone. All your data will be permanently deleted.

Are you absolutely sure you want to proceed?`;

    if (window.confirm(confirmMessage)) {
      cancelSubscriptionMutation.mutate();
    }
  };

  const handleDeleteFacebookData = () => {
    if (window.confirm("Are you sure you want to delete all Facebook data? This will remove all Facebook connections and cannot be undone.")) {
      deleteFacebookMutation.mutate();
    }
  };

  const handleDeleteInstagramData = () => {
    if (window.confirm("Are you sure you want to delete all Instagram data? This will remove all Instagram connections and cannot be undone.")) {
      deleteInstagramMutation.mutate();
    }
  };

  // Check if subscription is cancelled to show delete options
  const isSubscriptionCancelled = user?.subscriptionPlan === 'cancelled';
  
  // Log when delete data options are enabled
  useEffect(() => {
    if (user && isSubscriptionCancelled) {
      console.log(`Delete data options enabled for ${user.email}`);
    }
  }, [user, isSubscriptionCancelled]);

  if (!user) {
    return null;
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="h-10 w-10">
          <Menu className="h-5 w-5" />
          <span className="sr-only">User menu</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="profile-menu w-72 p-4">
        <div className="space-y-4">
          {/* User Info */}
          <div className="flex items-center space-x-3">
            <div className="flex-shrink-0">
              <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                <User className="h-5 w-5 text-primary" />
              </div>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{user.email}</p>
              <p className="text-xs text-muted-foreground">{user.phone}</p>
            </div>
          </div>

          <DropdownMenuSeparator />

          {/* Subscription Info */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Plan</span>
              <span className="text-sm text-primary capitalize">{user.subscriptionPlan}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Posts Remaining</span>
              <span className="text-sm">{user.remainingPosts} / {user.totalPosts}</span>
            </div>
            <div className="w-full bg-secondary rounded-full h-2">
              <div 
                className="bg-primary h-2 rounded-full transition-all duration-300" 
                style={{ width: `${(user.remainingPosts / user.totalPosts) * 100}%` }}
              />
            </div>
          </div>

          <DropdownMenuSeparator />

          {/* Actions */}
          <div className="space-y-1">
            <DropdownMenuItem
              onClick={() => setLocation("/profile")}
              className="cursor-pointer"
            >
              <User className="mr-2 h-4 w-4" />
              View Profile
            </DropdownMenuItem>
            
            <DropdownMenuItem
              onClick={() => setLocation("/brand-purpose")}
              className="cursor-pointer"
            >
              <Building2 className="mr-2 h-4 w-4" />
              Brand Purpose
            </DropdownMenuItem>

            <DropdownMenuItem
              onClick={() => setLocation("/schedule")}
              className="cursor-pointer"
            >
              <Calendar className="mr-2 h-4 w-4" />
              Social Schedule
            </DropdownMenuItem>

            <DropdownMenuItem
              onClick={() => setLocation("/platform-connections")}
              className="cursor-pointer"
            >
              <Share2 className="mr-2 h-4 w-4" />
              Platform Connect
            </DropdownMenuItem>

            <DropdownMenuItem
              onClick={() => setLocation("/analytics")}
              className="cursor-pointer"
            >
              <BarChart3 className="mr-2 h-4 w-4" />
              Analytics
            </DropdownMenuItem>

            <DropdownMenuSeparator />

            {/* Data Deletion Section - Only show if subscription is cancelled */}
            {isSubscriptionCancelled && (
              <>
                <div className="px-2 py-1">
                  <p className="text-xs font-medium text-muted-foreground mb-2">Data Management</p>
                </div>
                
                <DropdownMenuItem
                  onClick={handleDeleteFacebookData}
                  disabled={deleteFacebookMutation.isPending}
                  className="cursor-pointer text-orange-600 focus:text-orange-600"
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  {deleteFacebookMutation.isPending ? "Deleting..." : "Delete Facebook Data"}
                </DropdownMenuItem>

                <DropdownMenuItem
                  onClick={handleDeleteInstagramData}
                  disabled={deleteInstagramMutation.isPending}
                  className="cursor-pointer text-orange-600 focus:text-orange-600"
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  {deleteInstagramMutation.isPending ? "Deleting..." : "Delete Instagram Data"}
                </DropdownMenuItem>

                <DropdownMenuSeparator />
              </>
            )}
            
            {/* Only show Cancel Subscription if subscription is active */}
            {user?.subscriptionActive && user?.subscriptionPlan !== 'cancelled' && (
              <DropdownMenuItem
                onClick={handleCancelSubscription}
                disabled={cancelSubscriptionMutation.isPending}
                className="cursor-pointer text-destructive focus:text-destructive"
              >
                <CreditCard className="mr-2 h-4 w-4" />
                {cancelSubscriptionMutation.isPending ? "Cancelling..." : "Cancel Subscription"}
              </DropdownMenuItem>
            )}
            
            <DropdownMenuItem
              onClick={() => logoutMutation.mutate()}
              disabled={logoutMutation.isPending}
              className="cursor-pointer"
            >
              <LogOut className="mr-2 h-4 w-4" />
              {logoutMutation.isPending ? "Logging out..." : "Logout"}
            </DropdownMenuItem>
          </div>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}