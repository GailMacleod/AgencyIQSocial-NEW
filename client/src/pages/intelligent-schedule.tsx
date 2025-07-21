import { useLocation } from "wouter";
import { Calendar, Clock, CheckCircle, XCircle, RotateCcw, Play, Eye, ThumbsUp, X, Sparkles, Brain, Target, Users, MapPin, Edit3, Save } from "lucide-react";
import CalendarCard from "@/components/calendar-card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useState, useEffect } from "react";
import { format, addDays, startOfMonth, endOfMonth, isSameDay, isToday } from "date-fns";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";
import BackButton from "@/components/back-button";
import { MetaPixelTracker } from "@/lib/meta-pixel";
import AutoPostingEnforcer from "@/components/auto-posting-enforcer";
import VideoPostCardSimple from "@/components/VideoPostCardSimple";
import OnboardingWizard from "@/components/onboarding/OnboardingWizard";
import { TokenStatusBanner } from "@/components/TokenStatusBanner";

interface Post {
  id: number;
  platform: string;
  content: string;
  status: string;
  scheduledFor: string;
  publishedAt?: string;
  errorLog?: string;
  aiRecommendation?: string;
  aiScore?: number;
  localEvent?: string;
  strategicTheme?: string;
  businessCanvasPhase?: string;
  engagementOptimisation?: string;
  analytics?: {
    reach: number;
    engagement: number;
    impressions: number;
  };
  // Video approval fields
  hasVideo?: boolean;
  videoApproved?: boolean;
  videoData?: any;
  approvedAt?: string;
}

interface User {
  id: number;
  email: string;
  phone: string;
  subscriptionPlan: string;
  remainingPosts: number;
  totalPosts: number;
}

interface SubscriptionUsage {
  subscriptionPlan: string;
  totalAllocation: number;
  remainingPosts: number;
  usedPosts: number;
  publishedPosts: number;
  failedPosts: number;
  partialPosts: number;
  planLimits: {
    posts: number;
    reach: number;
    engagement: number;
  };
  usagePercentage: number;
}

interface BrandPurpose {
  id: number;
  brandName: string;
  productsServices: string;
  corePurpose: string;
  audience: string;
  jobToBeDone: string;
  motivations: string;
  painPoints: string;
  goals: any;
  contactDetails: any;
}

interface AIScheduleData {
  posts: Post[];
  analysis: {
    jtbdScore: number;
    platformWeighting: { [platform: string]: number };
    tone: string;
    postTypeAllocation: { [type: string]: number };
    suggestions: string[];
  };
  schedule: {
    optimalTimes: { [platform: string]: string[] };
    eventAlignment: string[];
    contentThemes: string[];
  };
}

function IntelligentSchedule() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [selectedDay, setSelectedDay] = useState<Date | null>(null);
  const [editingPost, setEditingPost] = useState<{id: number, content: string} | null>(null);
  const [editContent, setEditContent] = useState("");
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [approvedPosts, setApprovedPosts] = useState<Set<number>>(new Set());
  const [isGeneratingSchedule, setIsGeneratingSchedule] = useState(false);
  const [approvingPosts, setApprovingPosts] = useState<Set<number>>(new Set());
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const [successModalData, setSuccessModalData] = useState<{
    platform: string;
    postId: number;
    scheduledTime: string;
  } | null>(null);
  const [scheduleGenerated, setScheduleGenerated] = useState(false);
  const [aiInsights, setAiInsights] = useState<any>(null);
  const [calendarView, setCalendarView] = useState(false); // Default to List view to show VideoPostCard
  const [queenslandEvents, setQueenslandEvents] = useState<any[]>([]);

  const queryClient = useQueryClient();

  // Video handling
  const handleVideoApproved = async (postId: string, videoData: any) => {
    try {
      // Just refresh the posts query - the video approval is already handled by the backend
      queryClient.invalidateQueries({ queryKey: ['/api/posts'] });
      toast({
        title: "Video Approved!",
        description: "Video and text combined into approved post. Ready to publish!"
      });
    } catch (error) {
      console.error('Video approval failed:', error);
      toast({
        title: "Error", 
        description: "Failed to approve video content",
        variant: "destructive"
      });
    }
  };

  // Edit post content mutation
  const editPostMutation = useMutation({
    mutationFn: async ({ postId, content }: { postId: number; content: string }) => {
      const response = await apiRequest("PUT", `/api/posts/${postId}`, { content });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/posts'] });
      setIsEditModalOpen(false);
      setEditingPost(null);
      setEditContent("");
      toast({
        title: "Content Updated",
        description: "Post content has been successfully updated.",
      });
    },
    onError: () => {
      toast({
        title: "Update Failed",
        description: "Failed to update post content. Please try again.",
        variant: "destructive",
      });
    }
  });

  // Handle edit content button click
  const handleEditPost = (post: Post) => {
    console.log('Edit clicked for', post.platform);
    setEditingPost({ id: post.id, content: post.content });
    setEditContent(post.content);
    setIsEditModalOpen(true);
  };

  // Save edited content
  const saveEditedContent = () => {
    if (editingPost) {
      editPostMutation.mutate({ postId: editingPost.id, content: editContent });
    }
  };

  // Fetch user data (may be cached from login)
  const { data: user, isLoading: userLoading, error: userError } = useQuery({
    queryKey: ["/api/user"],
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Fetch user status data (cached from login)
  const { data: userStatus, isLoading: userStatusLoading } = useQuery({
    queryKey: ["/api/user-status"],
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Fetch brand purpose data
  const { data: brandPurpose, isLoading: brandLoading } = useQuery<BrandPurpose>({
    queryKey: ["/api/brand-purpose"],
    enabled: !!user && !userLoading,
  });

  // Fetch subscription usage for quota-aware generation
  const { data: subscriptionUsage, isLoading: subscriptionLoading, refetch: refetchSubscriptionUsage } = useQuery<SubscriptionUsage>({
    queryKey: ["/api/subscription-usage"],
    enabled: !!user && !userLoading,
    refetchOnMount: true,
    refetchOnWindowFocus: true,
    staleTime: 0, // Always fetch fresh quota data on navigation
  });

  // Check if user needs to choose subscription - redirect if no active subscription
  useEffect(() => {
    if (user && !userLoading && !subscriptionLoading) {
      // If user exists but has no subscription plan or it's empty/default
      if (!user.subscriptionPlan || user.subscriptionPlan === '' || user.subscriptionPlan === 'none') {
        console.log('User has no active subscription, redirecting to subscription selection');
        setLocation('/subscription');
        return;
      }
      
      // If user has subscription but subscriptionUsage shows no allocation
      if (subscriptionUsage && subscriptionUsage.totalAllocation === 0) {
        console.log('User subscription needs activation, redirecting to subscription selection');
        setLocation('/subscription');
        return;
      }
    }
  }, [user, userLoading, subscriptionUsage, subscriptionLoading, setLocation]);

  // Redirect to login if authentication failed
  useEffect(() => {
    if (userError && !userLoading) {
      console.log('Authentication failed, redirecting to login');
      setLocation('/login');
    }
  }, [userError, userLoading, setLocation]);

  // Fetch posts only after user is authenticated (may be cached from login)
  const { data: posts, isLoading: postsLoading, refetch: refetchPosts } = useQuery({
    queryKey: ["/api/posts"],
    enabled: !!user && !userLoading,
    retry: 2,
    staleTime: 2 * 60 * 1000, // 2 minutes
  });

  // Fetch analytics data (cached from login)
  const { data: analytics, isLoading: analyticsLoading } = useQuery({
    queryKey: ["/api/analytics"],
    enabled: !!user && !userLoading,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Force refresh when strategic content generation completes
  useEffect(() => {
    if (scheduleGenerated) {
      // Comprehensive cache reset after generation
      const performDelayedCacheReset = async () => {
        // Clear all cached data first
        queryClient.removeQueries({ queryKey: ["/api/posts"] });
        queryClient.removeQueries({ queryKey: ["/api/subscription-usage"] });
        queryClient.removeQueries({ queryKey: ["/api/user"] });
        queryClient.removeQueries({ queryKey: ["/api/user-status"] });
        
        // Invalidate all queries
        await queryClient.invalidateQueries({ queryKey: ["/api/posts"] });
        await queryClient.invalidateQueries({ queryKey: ["/api/subscription-usage"] });
        await queryClient.invalidateQueries({ queryKey: ["/api/user"] });
        await queryClient.invalidateQueries({ queryKey: ["/api/user-status"] });
        
        // Force fresh fetches
        await Promise.all([
          refetchPosts(),
          refetchSubscriptionUsage ? refetchSubscriptionUsage() : Promise.resolve()
        ]);
      };
      
      // Perform cache reset with multiple attempts
      setTimeout(performDelayedCacheReset, 500);
      setTimeout(performDelayedCacheReset, 1500);
      setTimeout(performDelayedCacheReset, 3000);
    }
  }, [scheduleGenerated, queryClient, refetchPosts, refetchSubscriptionUsage]);



  // Type-safe posts array
  const postsArray: Post[] = Array.isArray(posts) ? posts : [];

  // Fetch Queensland events for calendar optimisation
  useEffect(() => {
    const fetchQueenslandEvents = async () => {
      try {
        const response = await fetch('/api/queensland-events');
        if (response.ok) {
          const events = await response.json();
          setQueenslandEvents(events);
        }
      } catch (error) {
        console.log('Queensland events unavailable, using basic calendar');
      }
    };
    
    fetchQueenslandEvents();
  }, []);

  // QUOTA DISPLAY ONLY - No restrictions on navigation, editing, or generation
  useEffect(() => {
    if (subscriptionUsage && !subscriptionLoading) {
      console.log(`📊 Quota status: ${subscriptionUsage.remainingPosts}/${subscriptionUsage.totalAllocation} posts remaining (tracking published posts only)`);
      
      // Refresh quota data for accurate display
      queryClient.invalidateQueries({ queryKey: ["/api/subscription-usage"] });
    }
  }, [subscriptionUsage, subscriptionLoading, queryClient]);

  // Refresh UI when strategic content generation completes
  useEffect(() => {
    if (scheduleGenerated && !isGeneratingSchedule) {
      // Force refresh of posts to show new strategic content
      queryClient.invalidateQueries({ queryKey: ["/api/posts"] });
      refetchPosts();
      
      // Reset the flag after refresh
      setTimeout(() => {
        setScheduleGenerated(false);
      }, 1000);
    }
  }, [scheduleGenerated, isGeneratingSchedule, queryClient, refetchPosts]);

  // Generate calendar dates for next 30 days with AEST timezone consistency
  const generateCalendarDates = () => {
    const dates = [];
    // Get current date in AEST timezone
    const today = new Date(new Date().toLocaleString("en-US", { timeZone: "Australia/Brisbane" }));
    
    for (let i = 0; i < 30; i++) {
      const date = new Date(today);
      date.setDate(today.getDate() + i);
      // Ensure consistent AEST timezone for each generated date
      const aestDate = new Date(date.toLocaleString("en-US", { timeZone: "Australia/Brisbane" }));
      dates.push(aestDate);
    }
    
    return dates;
  };

  const calendarDates = generateCalendarDates();

  // Group posts by date with AEST timezone consistency
  const getPostsForDate = (date: Date): Post[] => {
    // Convert to AEST timezone for consistent date comparison
    const aestDate = new Date(date.toLocaleString("en-US", { timeZone: "Australia/Brisbane" }));
    const dateStr = aestDate.toISOString().split('T')[0];
    
    const filteredPosts = postsArray.filter(post => {
      if (!post.scheduledFor) return false;
      // Convert post scheduled date to AEST
      const postDate = new Date(post.scheduledFor);
      const aestPostDate = new Date(postDate.toLocaleString("en-US", { timeZone: "Australia/Brisbane" }));
      const postDateStr = aestPostDate.toISOString().split('T')[0];
      return postDateStr === dateStr;
    });
    
    // Strategic data properly flowing to calendar
    
    return filteredPosts;
  };

  // Get Queensland events for a specific date
  const getEventsForDate = (date: Date) => {
    const dateStr = date.toISOString().split('T')[0];
    return queenslandEvents.filter(event => event.date === dateStr);
  };

  // Approve and schedule individual post with loading state and success modal
  const approvePost = async (postId: number) => {
    // Find the post to get platform and scheduling details
    const post = postsArray.find(p => p.id === postId);
    if (!post) return;

    // Add to loading state
    setApprovingPosts(prev => new Set(prev).add(postId));

    try {
      const response = await fetch('/api/approve-post', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ postId })
      });

      if (response.ok) {
        setApprovedPosts(prev => {
          const newSet = new Set(prev);
          newSet.add(postId);
          return newSet;
        });
        queryClient.invalidateQueries({ queryKey: ['/api/posts'] });
        
        // Show success modal with post details
        setSuccessModalData({
          platform: post.platform,
          postId: postId,
          scheduledTime: post.scheduledFor || 'immediately'
        });
        setShowSuccessModal(true);
        
        toast({
          title: "Post Approved Successfully",
          description: `${post.platform} post scheduled for publishing`,
        });
      } else {
        throw new Error('Failed to approve post');
      }
    } catch (error) {
      toast({
        title: "Approval Failed",
        description: "Failed to approve post. Please try again.",
        variant: "destructive",
      });
    } finally {
      // Remove from loading state
      setApprovingPosts(prev => {
        const newSet = new Set(prev);
        newSet.delete(postId);
        return newSet;
      });
    }
  };

  // Generate strategic content using AI-powered methodology
  const generateIntelligentSchedule = async () => {
    if (!brandPurpose) {
      toast({
        title: "Brand Purpose Required",
        description: "Please complete your brand purpose setup first.",
        variant: "destructive",
      });
      setLocation("/brand-purpose");
      return;
    }

    setIsGeneratingSchedule(true);
    
    try {
      toast({
        title: "Strategic Content Generation in Progress",
        description: "Your little helper is creating strategic content with AI-powered analysis...",
      });

      // Use strategic content generation with quota reset
      const response = await fetch('/api/generate-strategic-content', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          brandPurpose,
          totalPosts: 52, // Professional plan allocation
          platforms: ['facebook', 'instagram', 'linkedin', 'x', 'youtube'],
          resetQuota: true // Reset quota to Professional plan
        })
      });

      if (response.ok) {
        const strategicData = await response.json();
        
        // Store strategic insights
        setAiInsights({
          jtbdScore: 95, // High score for strategic content
          platformWeighting: {
            facebook: 0.25,
            instagram: 0.20,
            linkedin: 0.20,
            x: 0.15,
            youtube: 0.20
          },
          tone: 'Strategic Business Professional',
          postTypeAllocation: {
            'authority-building': 0.3,
            'problem-solution': 0.25,
            'social-proof': 0.25,
            'urgency-conversion': 0.2
          },
          suggestions: [
            'AI methodology implemented',
            'Value Proposition Canvas integrated',
            'Queensland market data optimized',
            '30-day cycle optimisation active'
          ]
        });
        
        setScheduleGenerated(true);
        
        toast({
          title: "Strategic Content Generated Successfully",
          description: `Your little helper created ${strategicData.savedCount} strategic posts using AI-powered analysis and Value Proposition insights`,
        });

        // Comprehensive cache invalidation and refresh
        const performCacheReset = async () => {
          // Clear all cached data
          queryClient.removeQueries({ queryKey: ["/api/posts"] });
          queryClient.removeQueries({ queryKey: ["/api/subscription-usage"] });
          queryClient.removeQueries({ queryKey: ["/api/user"] });
          queryClient.removeQueries({ queryKey: ["/api/user-status"] });
          
          // Invalidate all related queries
          await queryClient.invalidateQueries({ queryKey: ["/api/posts"] });
          await queryClient.invalidateQueries({ queryKey: ["/api/subscription-usage"] });
          await queryClient.invalidateQueries({ queryKey: ["/api/user"] });
          await queryClient.invalidateQueries({ queryKey: ["/api/user-status"] });
          
          // Force fresh fetches
          await Promise.all([
            refetchPosts(),
            refetchSubscriptionUsage ? refetchSubscriptionUsage() : Promise.resolve()
          ]);
        };
        
        // Perform cache reset immediately and again after a short delay
        performCacheReset();
        setTimeout(performCacheReset, 1000);
      } else {
        const error = await response.json();
        throw new Error(error.message || 'Failed to generate strategic content');
      }
    } catch (error: any) {
      console.error('Error generating strategic content:', error);
      toast({
        title: "Strategic Content Generation Failed",
        description: error.message || "Failed to generate strategic content. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsGeneratingSchedule(false);
    }
  };

  // Auto-post entire intelligent schedule
  const autoPostIntelligentSchedule = async () => {
    try {
      toast({
        title: "Publishing Intelligent Schedule",
        description: "Auto-posting all AI-optimized content to your platforms...",
      });

      const response = await fetch('/api/direct-publish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'publish_all'
        })
      });

      if (response.ok) {
        const result = await response.json();
        
        toast({
          title: "Intelligent Schedule Published",
          description: `${result.successCount}/${result.totalPosts} AI-optimized posts published successfully`,
        });

        refetchPosts();
        
        // Invalidate platform connections to refresh connection state
        queryClient.invalidateQueries({ queryKey: ['/api/platform-connections'] });
      } else {
        const error = await response.json();
        
        // Handle quota exceeded error
        if (error.quotaExceeded) {
          toast({
            title: "Subscription Limit Reached",
            description: error.message,
            variant: "destructive",
          });
        } else {
          throw new Error(error.message || 'Failed to auto-post schedule');
        }
      }
    } catch (error: any) {
      console.error('Error auto-posting schedule:', error);
      toast({
        title: "Auto-posting Error",
        description: error.message || "Failed to auto-post schedule. Please try again.",
        variant: "destructive",
      });
    }
  };



  // Platform icons
  const getPlatformIcon = (platform: string) => {
    const iconClass = "w-4 h-4";
    switch (platform.toLowerCase()) {
      case 'facebook': return <div className={`${iconClass} bg-blue-600 text-white rounded flex items-center justify-center text-xs font-bold`}>f</div>;
      case 'instagram': return <div className={`${iconClass} bg-gradient-to-r from-purple-500 to-pink-500 text-white rounded flex items-center justify-center text-xs font-bold`}>ig</div>;
      case 'linkedin': return <div className={`${iconClass} bg-blue-700 text-white rounded flex items-center justify-center text-xs font-bold`}>in</div>;
      case 'x': return <div className={`${iconClass} bg-black text-white rounded flex items-center justify-center text-xs font-bold`}>x</div>;
      case 'youtube': return <div className={`${iconClass} bg-red-600 text-white rounded flex items-center justify-center text-xs font-bold`}>yt</div>;
      default: return <div className={`${iconClass} bg-gray-500 text-white rounded flex items-center justify-center text-xs`}>?</div>;
    }
  };

  // Show loading states
  if (userLoading || subscriptionLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-purple-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading your account...</p>
        </div>
      </div>
    );
  }

  // Don't render main content if user is being redirected
  if (!user || !subscriptionUsage || subscriptionUsage.totalAllocation === 0) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-purple-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Setting up your account...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <MasterHeader showUserMenu={true} />

      <div className="max-w-7xl mx-auto px-2 sm:px-4 lg:px-8 py-4 sm:py-8">
        <div className="mb-6">
          <BackButton to="/brand-purpose" label="Back to Brand Purpose" />
        </div>
        
        <div className="text-center mb-8">
          <p className="text-sm text-gray-600">Step 3 of 3</p>
          <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
            <div className="bg-purple-600 h-2 rounded-full w-full"></div>
          </div>
        </div>

        {/* AI Intelligence Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Brain className="w-8 h-8 text-purple-600 mr-3" />
            <h1 className="text-4xl font-bold text-gray-900">
              AI-Powered Content Schedule
            </h1>
            <Sparkles className="w-8 h-8 text-yellow-500 ml-3" />
          </div>
          <p className="text-gray-600 text-lg mb-6">
            xAI analyses your brand purpose, audience insights, and Queensland market data to create intelligent, strategic content
          </p>

          {/* OAuth Token Status Banner */}
          <TokenStatusBanner />



          {/* AI Analysis Insights */}
          {aiInsights && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <Card>
                <CardContent className="p-4 text-center">
                  <Target className="w-6 h-6 text-blue-600 mx-auto mb-2" />
                  <h3 className="font-medium text-gray-900">JTBD Score</h3>
                  <p className="text-2xl font-bold text-blue-600">{aiInsights.jtbdScore}/100</p>
                  <p className="text-xs text-gray-500">Strategic clarity</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <Users className="w-6 h-6 text-green-600 mx-auto mb-2" />
                  <h3 className="font-medium text-gray-900">Tone</h3>
                  <p className="text-lg font-medium text-green-600 capitalize">{aiInsights.tone}</p>
                  <p className="text-xs text-gray-500">Content style</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4 text-center">
                  <Sparkles className="w-6 h-6 text-purple-600 mx-auto mb-2" />
                  <h3 className="font-medium text-gray-900">Platform Focus</h3>
                  <p className="text-lg font-medium text-purple-600">
                    {Object.entries(aiInsights.platformWeighting)
                      .sort(([,a], [,b]) => (b as number) - (a as number))[0][0]}
                  </p>
                  <p className="text-xs text-gray-500">Primary platform</p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            {!scheduleGenerated ? (
              <Button
                onClick={generateIntelligentSchedule}
                disabled={!brandPurpose || isGeneratingSchedule}
                className="bg-purple-600 hover:bg-purple-700 text-white px-8 py-3 text-lg"
                size="lg"
              >
                {isGeneratingSchedule ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                    Generating Strategic Content...
                  </>
                ) : (
                  <>
                    <Brain className="w-5 h-5 mr-2" />
                    Generate Strategic Content
                  </>
                )}
              </Button>
            ) : (
              <Button
                onClick={autoPostIntelligentSchedule}
                className="bg-green-600 hover:bg-green-700 text-white px-8 py-3 text-lg"
                size="lg"
              >
                <Play className="w-5 h-5 mr-2" />
                Auto-Post Intelligent Schedule
              </Button>
            )}
          </div>
        </div>

        {/* Posts Loading State */}
        {postsLoading && (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Loading your intelligent content...</p>
          </div>
        )}

        {/* AI-Generated Posts Display */}
        {!postsLoading && postsArray.length > 0 && (
          <div className="mb-8">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-gray-900 flex items-center">
                <Sparkles className="w-6 h-6 text-purple-600 mr-2" />
                Your AI-Generated Content ({postsArray.length} posts)
              </h2>
              
              {/* View Toggle */}
              <div className="flex bg-gray-100 rounded-lg p-1">
                <button
                  onClick={() => setCalendarView(true)}
                  className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                    calendarView ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  <Calendar className="w-4 h-4 mr-1 inline" />
                  Calendar
                </button>
                <button
                  onClick={() => setCalendarView(false)}
                  className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                    !calendarView ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'
                  }`}
                >
                  List
                </button>
              </div>
            </div>

            {calendarView ? (
              // Calendar Grid View
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {calendarDates.map((date, index) => {
                  const postsForDate = getPostsForDate(date);
                  const eventsForDate = getEventsForDate(date);
                  
                  return (
                    <CalendarCard
                      key={index}
                      date={date}
                      posts={postsForDate}
                      events={eventsForDate}
                    />
                  );
                })}
              </div>
            ) : (
              // List View with Video Generation
              <div className="grid gap-6">
                {postsArray.length > 0 ? postsArray.map((post: Post) => (
                  <VideoPostCardSimple
                    key={post.id}
                    post={post}
                    onVideoApproved={handleVideoApproved}
                    userId={user?.id?.toString() || '2'}
                    onPostUpdate={() => refetchPosts()}
                  />
                )) : (
                  <div className="text-center p-8">
                    <p className="text-gray-500 mb-4">Loading posts... ({postsArray.length} posts loaded)</p>
                    <p className="text-sm text-gray-400">If no posts appear, generate content first.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Auto-Publishing Enforcer */}
        {postsArray.length > 0 && (
          <div className="mb-8">
            <AutoPostingEnforcer />
          </div>
        )}

        {/* Empty State */}
        {!postsLoading && postsArray.length === 0 && !isGeneratingSchedule && (
          <div className="text-center py-12 bg-white rounded-lg border">
            <Brain className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-xl font-medium text-gray-900 mb-2">No AI Content Generated Yet</h3>
            <p className="text-gray-500 mb-6 max-w-md mx-auto">
              Analyse your brand purpose, audience insights, to create intelligent, strategic content
            </p>
            {brandPurpose ? (
              <Button
                onClick={generateIntelligentSchedule}
                className="bg-purple-600 hover:bg-purple-700 text-white"
                size="lg"
                disabled={isGeneratingSchedule}
              >
                {isGeneratingSchedule ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2" />
                    <span className="hidden sm:inline">Generating AI Content...</span>
                    <span className="sm:hidden">Generating...</span>
                  </>
                ) : (
                  <>
                    <Brain className="w-5 h-5 mr-2" />
                    <span className="hidden sm:inline">Generate AI Content</span>
                    <span className="sm:hidden">Generate</span>
                  </>
                )}
              </Button>
            ) : (
              <Button
                onClick={() => setLocation("/brand-purpose")}
                className="bg-blue-600 hover:bg-blue-700 text-white"
                size="lg"
              >
                <Target className="w-5 h-5 mr-2" />
                Complete Brand Purpose First
              </Button>
            )}
          </div>
        )}
      </div>
      
      {/* Training Wizard */}
      <div className="fixed bottom-4 right-4 z-50">
        <OnboardingWizard />
      </div>
      
      <MasterFooter />
    </div>
  );
}

export default IntelligentSchedule;
