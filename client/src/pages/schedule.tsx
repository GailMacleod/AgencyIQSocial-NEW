import { useLocation } from "wouter";
import { Calendar, Clock, CheckCircle, XCircle, RotateCcw, Play, Eye, ThumbsUp, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { useState, useEffect } from "react";
import { format, addDays, startOfMonth, endOfMonth, isSameDay, isToday } from "date-fns";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";
import BackButton from "@/components/back-button";
import BrandSync from "@/components/Schedule";
import CMOStrategy from "@/components/CMOStrategy";
import VideoPostCardSimple from "@/components/VideoPostCardSimple";

interface Post {
  id: number;
  platform: string;
  content: string;
  status: string;
  scheduledFor: string;
  publishedAt?: string;
  errorLog?: string;
  aiRecommendation?: string;
  localEvent?: string;
  analytics?: {
    reach: number;
    engagement: number;
    impressions: number;
  };
}

interface User {
  id: number;
  email: string;
  phone: string;
  subscriptionPlan: string;
  remainingPosts: number;
  totalPosts: number;
}

interface CalendarDay {
  date: Date;
  posts: Post[];
  aiInsight?: string;
  localEvents?: string[];
  isOptimalDay: boolean;
}

export default function Schedule() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  
  const [currentMonth, setCurrentMonth] = useState(new Date());
  const [hoveredDay, setHoveredDay] = useState<Date | null>(null);
  const [selectedDay, setSelectedDay] = useState<Date | null>(null);
  const [showAIThinking, setShowAIThinking] = useState(false);
  const [aiStep, setAIStep] = useState(0);
  const [generatedPosts, setGeneratedPosts] = useState<Post[]>([]);
  const [approvedPosts, setApprovedPosts] = useState<Set<number>>(new Set());
  const [editingPost, setEditingPost] = useState<{id: number, content: string} | null>(null);
  const [listFilter, setListFilter] = useState<'all' | 'draft' | 'approved' | 'published'>('all');

  // Initialize brand sync component
  const brandSync = BrandSync();

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as HTMLElement;
      if (selectedDay && !target.closest('.fixed.z-50')) {
        setSelectedDay(null);
      }
    };

    if (selectedDay) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [selectedDay]);

  // Handle day selection for dropdown
  const handleDayClick = (date: Date) => {
    if (selectedDay && isSameDay(selectedDay, date)) {
      setSelectedDay(null); // Close if clicking same day
    } else {
      setSelectedDay(date); // Open dropdown for selected day
    }
  };

  // Edit post content with proper error handling and state updates
  const saveEditedPost = async (postId: number, newContent: string) => {
    try {
      console.log(`Saving edited post ${postId} with new content:`, newContent);
      
      // Update database first
      const response = await fetch(`/api/posts/${postId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ content: newContent })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to update post');
      }

      const updatedPost = await response.json();
      console.log('Post updated successfully:', updatedPost);

      // Update local state after successful API call
      setGeneratedPosts(prev => 
        prev.map(post => 
          post.id === postId 
            ? { ...post, content: newContent }
            : post
        )
      );

      // Refresh posts data to ensure consistency
      await refetchPosts();

      setEditingPost(null);
      toast({
        title: "Post Updated",
        description: "Content has been saved successfully.",
      });
    } catch (error: any) {
      console.error('Error saving edited post:', error);
      toast({
        title: "Error",
        description: error.message || "Failed to save changes.",
        variant: "destructive",
      });
    }
  };

  // Approve post for specific day
  const approvePostForDay = async (dayDate: Date, postId?: number, publishNow?: boolean) => {
    try {
      // Find posts for this day or create a new one
      const dayPosts = generatedPosts.filter(post => 
        isSameDay(new Date(post.scheduledFor), dayDate)
      );

      if (dayPosts.length > 0) {
        // Approve existing post
        const postToApprove = postId ? 
          dayPosts.find(p => p.id === postId) : 
          dayPosts[0];
        
        if (postToApprove) {
          await approvePost(postToApprove.id, publishNow);
        }
      } else {
        // Create and approve a new post for this day
        const newPost: Post = {
          id: Date.now() + Math.random(),
          platform: 'facebook',
          content: `Auto-generated content for ${format(dayDate, 'MMMM d, yyyy')}`,
          status: 'approved',
          scheduledFor: dayDate.toISOString(),
          aiRecommendation: 'Optimized for daily engagement'
        };

        setGeneratedPosts(prev => [...prev, newPost]);
        setApprovedPosts(prev => {
          const newSet = new Set(prev);
          newSet.add(newPost.id);
          return newSet;
        });
        
        toast({
          title: publishNow ? "Post Created & Published" : "Post Created & Approved",
          description: `Content ${publishNow ? 'published' : 'scheduled'} for ${format(dayDate, 'MMM d')}`,
        });
      }
    } catch (error) {
      console.error('Error approving post for day:', error);
      toast({
        title: "Error",
        description: "Failed to approve post for this day.",
        variant: "destructive",
      });
    }
  };

  // Handle post approval and publishing to social media platforms
  const approvePost = async (postId: number, shouldPublishNow: boolean = false) => {
    try {
      // Immediately update UI state
      setApprovedPosts(prev => {
        const newSet = new Set(prev);
        newSet.add(postId);
        return newSet;
      });

      // Update generated posts state
      setGeneratedPosts(prev => 
        prev.map(post => 
          post.id === postId 
            ? { ...post, status: 'approved' }
            : post
        )
      );
      
      // Find the post in either generated posts or database posts
      const targetPost = generatedPosts.find(p => p.id === postId) || 
                        postsArray.find(p => p.id === postId);
      
      if (targetPost) {
        // Save to database and potentially publish immediately
        if (generatedPosts.find(p => p.id === postId)) {
          const response = await fetch('/api/posts', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
              platform: targetPost.platform,
              content: targetPost.content,
              scheduledFor: targetPost.scheduledFor,
              status: 'approved'
            })
          });

          if (response.ok) {
            const savedPost = await response.json();
            console.log('Post saved to database:', savedPost);
            
            // Auto-publish if requested and scheduled for now or past
            if (shouldPublishNow || new Date(targetPost.scheduledFor) <= new Date()) {
              await publishPost(savedPost.id, targetPost.platform);
            }
          }
        } else {
          // Update existing database post
          const response = await fetch(`/api/posts/${postId}`, {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ status: 'approved' })
          });

          if (response.ok) {
            refetchPosts();
            
            // Auto-publish if requested
            if (shouldPublishNow) {
              await publishPost(postId, targetPost.platform);
            }
          }
        }

        toast({
          title: shouldPublishNow ? "Post Published" : "Post Approved",
          description: shouldPublishNow ? 
            "Post has been published to your platform successfully." : 
            "Post has been approved and scheduled successfully.",
        });
      }
    } catch (error) {
      console.error('Error approving post:', error);
      // Revert state changes on error
      setApprovedPosts(prev => {
        const newSet = new Set(prev);
        newSet.delete(postId);
        return newSet;
      });
      setGeneratedPosts(prev => 
        prev.map(post => 
          post.id === postId 
            ? { ...post, status: 'draft' }
            : post
        )
      );
      toast({
        title: "Error",
        description: "Failed to approve post. Please try again.",
        variant: "destructive",
      });
    }
  };

  // Publish post to social media platform with subscription tracking
  const publishPost = async (postId: number, platform: string) => {
    try {
      // Show publishing progress
      toast({
        title: "Publishing Post",
        description: `Publishing to ${platform}...`,
      });

      const response = await fetch('/api/publish-post', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          postId,
          platform
        })
      });

      const result = await response.json();

      if (response.ok && result.success) {
        toast({
          title: "Post Published Successfully",
          description: `Your post has been published to ${platform} and counted against your subscription.`,
        });
        
        // Update local state to show published status
        setGeneratedPosts(prev => 
          prev.map(post => 
            post.id === postId 
              ? { ...post, status: 'published' }
              : post
          )
        );
        
        // Refresh posts to show updated status
        refetchPosts();
      } else {
        // Handle subscription limit reached
        if (result.subscriptionLimitReached) {
          toast({
            title: "Subscription Limit Reached",
            description: result.message,
            variant: "destructive",
          });
        } else {
          toast({
            title: "Publication Failed",
            description: result.message || result.error || 'Failed to publish post',
            variant: "destructive",
          });
        }
      }
    } catch (error: any) {
      console.error('Error publishing post:', error);
      toast({
        title: "Publication Error",
        description: "Network error occurred while publishing. Please check your connection and try again.",
        variant: "destructive",
      });
    }
  };

  // Auto-post entire 30-day schedule using direct-publish with publish_all action
  const autoPostEntireSchedule = async () => {
    try {
      setShowAIThinking(true);
      setAIStep(0);

      toast({
        title: "Auto-posting Schedule",
        description: "Publishing all approved posts to your connected platforms...",
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
        setShowAIThinking(false);
        
        toast({
          title: "Schedule Published",
          description: `${result.successCount}/${result.totalPosts} posts published successfully`,
        });

        // Refresh posts to show updated status
        refetchPosts();
        
        // Invalidate platform connections to refresh connection state
        queryClient.invalidateQueries({ queryKey: ['/api/platform-connections'] });
      } else {
        const error = await response.json();
        setShowAIThinking(false);
        
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
      setShowAIThinking(false);
      
      toast({
        title: "Auto-posting Error",
        description: error.message || "Failed to auto-post schedule. Please try again.",
        variant: "destructive",
      });
    }
  };

  // Bulk delete posts mutation
  const bulkDeleteMutation = useMutation({
    mutationFn: async ({ postIds, deleteAll }: { postIds?: number[], deleteAll?: boolean }) => {
      const response = await fetch('/api/posts/bulk', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ postIds, deleteAll })
      });
      
      if (!response.ok) {
        throw new Error('Failed to delete posts');
      }
      
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Posts Deleted",
        description: data.message,
      });
      refetchPosts();
      setGeneratedPosts([]);
    },
    onError: (error) => {
      toast({
        title: "Delete Failed",
        description: "Failed to delete posts. Please try again.",
        variant: "destructive",
      });
    }
  });

  // Fetch user data
  const { data: user, isLoading: userLoading } = useQuery({
    queryKey: ["/api/user"],
  });

  // Fetch brand purpose data
  const { data: brandPurposeData } = useQuery({
    queryKey: ["/api/brand-purpose"],
    enabled: !!user && !userLoading,
  });

  // Fetch posts only after user is authenticated
  const { data: posts, isLoading: postsLoading, refetch: refetchPosts } = useQuery({
    queryKey: ["/api/posts"],
    enabled: !!user && !userLoading,
    retry: 2,
    staleTime: 30000,
  });

  // Combine all posts from both API and generated state
  const apiPosts: Post[] = Array.isArray(posts) ? posts : [];
  const statePosts: Post[] = Array.isArray(generatedPosts) ? generatedPosts : [];
  
  // Merge posts, avoiding duplicates by ID
  const allPostsMap = new Map<number, Post>();
  [...apiPosts, ...statePosts].forEach(post => {
    allPostsMap.set(post.id, post);
  });
  const postsArray: Post[] = Array.from(allPostsMap.values());
  
  // Filter posts based on selected filter
  const filteredPosts = postsArray.filter(post => {
    switch (listFilter) {
      case 'draft':
        return post.status === 'draft' || !post.status;
      case 'approved':
        return post.status === 'approved';
      case 'published':
        return post.status === 'published';
      default:
        return true;
    }
  });
  
  // Debug logging
  console.log('Schedule Debug:', {
    user,
    userLoading,
    posts,
    postsLoading,
    postsArray: postsArray.length,
    postsArrayData: postsArray
  });

  // Platform icon component
  const getPlatformIcon = (platform: string) => {
    const iconClass = "w-4 h-4 text-blue-600";
    
    switch (platform.toLowerCase()) {
      case 'facebook':
        return <div className={iconClass}>f</div>;
      case 'instagram':
        return <div className={iconClass}>ig</div>;
      case 'linkedin':
        return <div className={iconClass}>in</div>;
      case 'x':
      case 'twitter':
        return <div className={iconClass}>x</div>;
      case 'youtube':
        return <div className={iconClass}>yt</div>;
      default:
        return <div className={iconClass}>?</div>;
    }
  };

  // Calendar day generation and optimization
  const getOptimalPostingDay = (date: Date): boolean => {
    const dayOfWeek = date.getDay();
    // Tuesday, Wednesday, Thursday are considered optimal
    return dayOfWeek >= 2 && dayOfWeek <= 4;
  };

  const getLocalEvents = (date: Date): string[] => {
    const dateStr = format(date, 'yyyy-MM-dd');
    const events: { [key: string]: string[] } = {
      // Queensland specific events
      '2025-06-10': ['Queensland SME Expo - Brisbane Convention Centre'],
      '2025-06-11': ['Digital Marketing Workshop - Gold Coast'],
      '2025-06-12': ['Small Business Network Event - Sunshine Coast'],
      '2025-06-15': ['Queensland Day'],
      '2025-06-16': ['Queensland Business Awards Opening'],
      '2025-06-17': ['Local Chamber of Commerce Meeting'],
    };
    
    return events[dateStr] || [];
  };

  const getAIInsight = (date: Date, events: string[]): string => {
    if (events.length > 0) {
      return `Perfect timing for ${events[0].split(' - ')[0]}! Consider posting about industry trends or business networking.`;
    }
    
    if (getOptimalPostingDay(date)) {
      return "High engagement day! Great for sharing valuable content and industry insights.";
    }
    
    return "Consider lighter content like behind-the-scenes or community highlights.";
  };

  // Generate calendar days
  const calendarDays: CalendarDay[] = [];
  const startDate = new Date();
  
  for (let i = 0; i < 30; i++) {
    const date = addDays(startDate, i);
    const localEvents = getLocalEvents(date);
    const dayPosts = postsArray.filter((post: Post) => 
      isSameDay(new Date(post.scheduledFor), date)
    );

    calendarDays.push({
      date,
      posts: dayPosts,
      aiInsight: getAIInsight(date, localEvents),
      localEvents,
      isOptimalDay: getOptimalPostingDay(date)
    });
  }

  // Show loading states
  if (userLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-purple-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading your account...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <p className="text-gray-600">Please wait while we authenticate your session...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <MasterHeader showUserMenu={true} />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <BackButton to="/brand-purpose" label="Back to Brand Purpose" />
        </div>
        
        <div className="text-center mb-8">
          <p className="text-sm text-gray-600">Step 3 of 3</p>
          <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
            <div className="bg-purple-600 h-2 rounded-full w-full"></div>
          </div>
        </div>

        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Your 30-Day Social Media Schedule
          </h1>
          <p className="text-gray-600">
            AI has analysed Queensland events and optimal posting times to create your personalised content calendar
          </p>
          
          {/* Auto-post entire schedule button */}
          <div className="mt-6 space-y-4">
            <div className="flex gap-4 justify-center">
              <Button
                onClick={autoPostEntireSchedule}
                className="bg-purple-600 hover:bg-purple-700 text-white px-8 py-3 text-lg"
                size="lg"
              >
                Auto-Post Entire 30-Day Schedule
              </Button>
              
              {postsArray.length > 0 && (
                <Button
                  onClick={() => bulkDeleteMutation.mutate({ deleteAll: true })}
                  variant="outline"
                  className="border-red-500 text-red-600 hover:bg-red-50 px-6 py-3 text-lg"
                  size="lg"
                  disabled={bulkDeleteMutation.isPending}
                >
                  {bulkDeleteMutation.isPending ? "Deleting..." : "Clear All Posts"}
                </Button>
              )}
            </div>
            
            <div className="text-center space-y-1">
              <p className="text-sm text-gray-500">
                Publishes all approved posts to your connected platforms
              </p>
              {postsArray.length > 0 && (
                <p className="text-xs text-red-500">
                  Clear posts if content is not relevant to regenerate fresh schedule
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Posts Loading State */}
        {postsLoading && (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Loading your posts...</p>
          </div>
        )}

        {/* CMO Brand Domination Strategy */}
        <div className="mb-8">
          <CMOStrategy 
            brandPurpose={brandPurposeData}
            onStrategyGenerated={(posts) => {
              // Refresh posts after CMO strategy generation
              refetchPosts();
              toast({
                title: "Brand Domination Strategy Deployed",
                description: `${posts.length} unstoppable posts generated for explosive business growth`,
              });
            }}
          />
        </div>

        {/* Main Post List */}
        {!postsLoading && (
          <div className="mb-8">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">Your Posts ({postsArray.length})</h2>
            
            {/* Filter Tabs */}
            <div className="flex space-x-1 mb-6 bg-gray-100 rounded-lg p-1">
              <Button
                onClick={() => setListFilter('all')}
                variant={listFilter === 'all' ? 'default' : 'ghost'}
                size="sm"
                className="flex-1 lowercase"
              >
                all posts ({postsArray.length})
              </Button>
              <Button
                onClick={() => setListFilter('draft')}
                variant={listFilter === 'draft' ? 'default' : 'ghost'}
                size="sm"
                className="flex-1 lowercase"
              >
                drafts ({postsArray.filter(p => p.status === 'draft' || !p.status).length})
              </Button>
              <Button
                onClick={() => setListFilter('approved')}
                variant={listFilter === 'approved' ? 'default' : 'ghost'}
                size="sm"
                className="flex-1 lowercase"
              >
                approved ({postsArray.filter(p => p.status === 'approved').length})
              </Button>
              <Button
                onClick={() => setListFilter('published')}
                variant={listFilter === 'published' ? 'default' : 'ghost'}
                size="sm"
                className="flex-1 lowercase"
              >
                published ({postsArray.filter(p => p.status === 'published').length})
              </Button>
            </div>

            {/* Scrollable Posts Container - Show all 30 days of posts */}
            <div className="max-h-screen overflow-y-auto space-y-4 pr-2">
              {filteredPosts.length > 0 ? (
                filteredPosts.map((post: Post) => (
                  <VideoPostCardSimple 
                    key={post.id} 
                    post={post} 
                    userId={user?.id} 
                    onVideoApproved={() => refetchPosts()}
                    onPostUpdate={() => refetchPosts()}
                  />
                ))
              ) : (
                <div className="text-center py-12 text-gray-500">
                  <Calendar className="w-16 h-16 mx-auto mb-4 opacity-50" />
                  <p className="text-lg mb-4">No posts found for this filter</p>
                  {listFilter === 'all' && (
                    <p className="text-sm text-gray-400">Generate posts using the CMO Brand Domination Strategy above</p>
                  )}
                </div>
              )}
            </div>
          </div>
        )}



        {/* Calendar Grid */}
        <div className="grid grid-cols-7 gap-4 mb-8">
          {['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'].map(day => (
            <div key={day} className="text-center font-medium text-gray-500 py-2 lowercase">
              {day}
            </div>
          ))}
          
          {calendarDays.map((day, index) => (
            <Card 
              key={index} 
              className={`relative h-32 cursor-pointer transition-all duration-200 hover:shadow-lg ${
                isToday(day.date) ? 'ring-2 ring-blue-500' : ''
              } ${
                selectedDay && isSameDay(selectedDay, day.date) ? 'ring-2 ring-purple-500' : ''
              } ${
                day.isOptimalDay ? 'bg-green-50 border-green-200' : ''
              }`}
              onClick={() => handleDayClick(day.date)}
            >
              <CardContent className="p-3 h-full">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-sm font-medium text-gray-900">
                    {format(day.date, 'd')}
                  </span>
                  {day.posts.length > 0 && (
                    <span className="text-xs bg-blue-100 text-blue-800 px-1 rounded">
                      {day.posts.length}
                    </span>
                  )}
                </div>
                
                {/* Posts */}
                {day.posts.slice(0, 2).map((post, postIndex) => (
                  <div key={postIndex} className="text-xs text-gray-600 mb-1 truncate">
                    {getPlatformIcon(post.platform)} {post.content.substring(0, 20)}...
                  </div>
                ))}
                
                {day.posts.length > 2 && (
                  <div className="text-xs text-gray-500">
                    +{day.posts.length - 2} more
                  </div>
                )}
                
                {/* Local Events */}
                {day.localEvents && day.localEvents.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {day.localEvents.map((event, idx) => (
                      <div key={idx} className="event-card bg-orange-50 border border-orange-200 rounded px-2 py-1">
                        <div className="text-xs text-orange-700 font-medium">
                          {event.split(' - ')[0]}
                        </div>
                        {event.includes(' - ') && (
                          <div className="text-xs text-orange-600">
                            {event.split(' - ')[1]}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Stable Day Dropdown for Approve & Post */}
        {selectedDay && (
          <div 
            className="fixed inset-0 bg-black bg-opacity-50" 
            style={{ zIndex: 9998 }}
            onClick={(e) => {
              if (e.target === e.currentTarget) {
                setSelectedDay(null);
              }
            }}
          >
            <Card className="fixed bg-white border-2 border-blue-500 shadow-xl p-6 max-w-md" style={{
              left: '50%',
              top: '50%',
              transform: 'translate(-50%, -50%)',
              zIndex: 9999,
              pointerEvents: 'auto'
            }}>
              <CardContent className="p-0">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900 lowercase">
                    {format(selectedDay, 'MMMM d, yyyy')}
                  </h3>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setSelectedDay(null)}
                    className="text-gray-500 hover:text-gray-700"
                  >
                    <X className="w-4 h-4" />
                  </Button>
                </div>

                {/* Posts for this day */}
                <div className="mb-4">
                  {(() => {
                    // Combine generated posts and brand posts for this day
                    const generatedDayPosts = generatedPosts.filter(post => 
                      isSameDay(new Date(post.scheduledFor), selectedDay)
                    );
                    const brandDayPosts = brandSync.getPostsForDay(selectedDay);
                    const dayPosts = [...generatedDayPosts, ...brandDayPosts];
                    
                    if (dayPosts.length > 0) {
                      return (
                        <div className="space-y-3">
                          <p className="text-sm text-gray-600 lowercase">scheduled posts:</p>
                          {dayPosts.map(post => (
                            <div key={post.id} className="bg-gray-50 rounded-lg p-3">
                              <div className="flex items-center space-x-2 mb-2">
                                {getPlatformIcon(post.platform)}
                                <span className="text-sm font-medium lowercase">{post.platform}</span>
                                <Badge variant={post.status === 'approved' ? 'default' : 'outline'}>
                                  {post.status}
                                </Badge>
                              </div>
                              
                              {/* Editable content */}
                              {editingPost?.id === post.id ? (
                                <div className="mb-3 bg-blue-50 p-3 rounded border-2 border-blue-200">
                                  <label className="block text-xs font-medium text-blue-800 mb-1">
                                    Edit content:
                                  </label>
                                  <textarea
                                    value={editingPost.content || ''}
                                    onChange={(e) => setEditingPost({...editingPost, content: e.target.value})}
                                    className="w-full p-2 border-2 border-blue-300 rounded text-sm resize-none focus:border-blue-500"
                                    rows={4}
                                    autoFocus
                                    placeholder="Enter your post content..."
                                  />
                                  <div className="flex justify-between items-center mt-2">
                                    <span className="text-xs text-gray-500">
                                      {(editingPost.content || '').length} chars
                                    </span>
                                    <div className="flex space-x-2">
                                      <Button
                                        onClick={() => saveEditedPost(post.id, editingPost.content || '')}
                                        size="sm"
                                        className="bg-blue-600 hover:bg-blue-700 text-white"
                                        disabled={!editingPost.content?.trim()}
                                      >
                                        Save
                                      </Button>
                                      <Button
                                        onClick={() => setEditingPost(null)}
                                        size="sm"
                                        variant="outline"
                                      >
                                        Cancel
                                      </Button>
                                    </div>
                                  </div>
                                </div>
                              ) : (
                                <div className="bg-gray-50 border rounded p-3 mb-3">
                                  <div className="flex items-center space-x-2 mb-1">
                                    <span className="text-xs font-medium text-purple-600 uppercase">
                                      Grok AI Content
                                    </span>
                                    <Badge variant="outline" className="text-xs">
                                      {post.platform}
                                    </Badge>
                                  </div>
                                  <p className="text-sm text-gray-900 leading-relaxed whitespace-pre-wrap">
                                    {post.content}
                                  </p>
                                </div>
                              )}

                              {/* Action buttons */}
                              {editingPost?.id !== post.id && (
                                <div className="flex space-x-2">
                                  <Button
                                    onClick={() => setEditingPost({id: post.id, content: post.content})}
                                    size="sm"
                                    variant="outline"
                                    className="lowercase"
                                  >
                                    edit
                                  </Button>
                                  
                                  {post.status === 'published' ? (
                                    <div className="flex items-center space-x-2">
                                      <span className="text-sm text-green-600 font-medium">✓ Published to {post.platform}</span>
                                      <Button
                                        onClick={() => {
                                          toast({
                                            title: "Post Already Published",
                                            description: `This post has been successfully published to ${post.platform} and counted against your subscription.`,
                                          });
                                        }}
                                        variant="outline"
                                        size="sm"
                                        className="text-xs"
                                      >
                                        view status
                                      </Button>
                                    </div>
                                  ) : post.status === 'approved' ? (
                                    <div className="flex space-x-2">
                                      <Button
                                        onClick={() => publishPost(post.id, post.platform)}
                                        className="approve-button bg-blue-600 hover:bg-blue-700 text-white text-sm lowercase"
                                        size="sm"
                                      >
                                        <Play className="w-4 h-4 mr-2" />
                                        approve & auto-post
                                      </Button>
                                      <Button
                                        onClick={() => {
                                          toast({
                                            title: "Post Status: Approved Only",
                                            description: "This post is approved but not yet published to social media platform. Click 'Approve & Auto-Post' to publish it.",
                                          });
                                        }}
                                        variant="outline"
                                        size="sm"
                                        className="text-xs"
                                      >
                                        status: approved only
                                      </Button>
                                    </div>
                                  ) : (
                                    <>
                                      <Button
                                        onClick={() => approvePostForDay(selectedDay, post.id, false)}
                                        className="approve-button bg-green-600 hover:bg-green-700 text-white text-sm lowercase"
                                        size="sm"
                                      >
                                        <CheckCircle className="w-4 h-4 mr-2" />
                                        approve & schedule
                                      </Button>
                                      <Button
                                        onClick={() => publishPost(post.id, post.platform)}
                                        className="approve-button bg-blue-600 hover:bg-blue-700 text-white text-sm lowercase"
                                        size="sm"
                                      >
                                        <Play className="w-4 h-4 mr-2" />
                                        approve & auto-post
                                      </Button>
                                    </>
                                  )}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      );
                    } else {
                      return (
                        <div className="text-center py-8">
                          <p className="text-gray-500 mb-4 lowercase">no content scheduled for this day</p>
                          <Button
                            onClick={() => approvePostForDay(selectedDay)}
                            className="bg-purple-600 hover:bg-purple-700 text-white lowercase"
                          >
                            create & approve post
                          </Button>
                        </div>
                      );
                    }
                  })()}

                  <div className="text-xs text-gray-500 text-center lowercase">
                    click outside to close
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* ANALYTICS BUTTON - BRIGHT AND VISIBLE */}
        <div className="w-full bg-gradient-to-r from-red-500 to-orange-500 text-white p-8 rounded-lg mt-6 shadow-2xl border-4 border-yellow-400">
          <div className="text-center">
            <h2 className="text-2xl font-black mb-4 uppercase tracking-wide">NEXT STEP</h2>
            <Button
              onClick={() => setLocation("/analytics")}
              className="bg-white text-red-600 hover:bg-yellow-100 px-12 py-4 text-2xl font-black rounded-lg shadow-xl border-4 border-yellow-400 uppercase tracking-wide"
              size="lg"
            >
              VIEW ANALYTICS
            </Button>
            <p className="mt-4 text-xl font-bold">
              Click here to see your results!
            </p>
          </div>
        </div>
      </div>

      <MasterFooter />
      
      {/* Fixed Floating Analytics Button */}
      <div className="fixed bottom-6 right-6 z-50">
        <Button
          onClick={() => setLocation("/analytics")}
          className="bg-purple-600 hover:bg-purple-700 text-white px-8 py-4 text-lg rounded-full font-bold shadow-2xl hover:shadow-3xl transition-all duration-300 transform hover:scale-110 border-4 border-white"
          size="lg"
        >
          📊 ANALYTICS →
        </Button>
      </div>
    </div>
  );
}