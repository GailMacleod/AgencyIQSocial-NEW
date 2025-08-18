import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Calendar, CheckCircle, Clock, AlertTriangle, RefreshCw, Send } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from '@/lib/queryClient';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

interface PostSchedule {
  postId: string;
  userId: string;
  content: string;
  platform: string;
  status: 'draft' | 'scheduled' | 'posted';
  isCounted: boolean;
  scheduledAt: string;
  createdAt: string;
}

interface QuotaStatus {
  quota: number;
  usedPosts: number;
  remainingPosts: number;
  subscriptionTier: string;
  periodStart: string;
  lastPosted: string | null;
  canPost: boolean;
  draftCount: number;
  postedCount: number;
  totalScheduled: number;
}

const platformIcons: Record<string, string> = {
  facebook: '👥',
  instagram: '📸',
  linkedin: '💼',
  x: '🐦',
  youtube: '📺'
};

const platformColors: Record<string, string> = {
  facebook: 'bg-blue-500',
  instagram: 'bg-pink-500',
  linkedin: 'bg-blue-700',
  x: 'bg-black',
  youtube: 'bg-red-500'
};

export function ScheduleManager() {
  const [showUpgradeModal, setShowUpgradeModal] = useState(false);
  const [showConnectionModal, setShowConnectionModal] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch quota status
  const { data: quotaStatus, isLoading: quotaLoading } = useQuery<QuotaStatus>({
    queryKey: ['/api/quota-status'],
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Fetch schedule
  const { data: scheduleData, isLoading: scheduleLoading } = useQuery<{ posts: PostSchedule[] }>({
    queryKey: ['/api/schedule'],
    enabled: !!quotaStatus,
  });

  // Generate schedule mutation
  const generateScheduleMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest('/api/generate-schedule', 'POST');
    },
    onSuccess: (data: any) => {
      if (data.quotaLimitReached) {
        setShowUpgradeModal(true);
        return;
      }
      
      toast({
        title: "Schedule Generated",
        description: `Generated ${data.generatedNewDrafts} new draft posts. ${data.remainingPosts} posts remaining in your quota.`,
      });
      
      queryClient.invalidateQueries({ queryKey: ['/api/quota-status'] });
      queryClient.invalidateQueries({ queryKey: ['/api/schedule'] });
    },
    onError: (error: any) => {
      if (error.message.includes('quota') || error.message.includes('limit')) {
        setShowUpgradeModal(true);
      } else if (error.message.includes('Connect your social media accounts') || error.message.includes('requiresConnection')) {
        setShowConnectionModal(true);
      } else {
        toast({
          title: "Generation Failed",
          description: error.message || "Failed to generate schedule",
          variant: "destructive",
        });
      }
    },
  });

  // Approve and post mutation
  const approvePostMutation = useMutation({
    mutationFn: async (postId: string) => {
      return await apiRequest('/api/approve-post', 'POST', { postId });
    },
    onSuccess: (data: any, postId) => {
      toast({
        title: "Post Published",
        description: `Successfully posted to ${data.platform || 'platform'}!`,
      });
      
      queryClient.invalidateQueries({ queryKey: ['/api/quota-status'] });
      queryClient.invalidateQueries({ queryKey: ['/api/schedule'] });
    },
    onError: (error: any, postId) => {
      if (error.message.includes('quota') || error.message.includes('limit') || error.message.includes('Post limit reached')) {
        setShowUpgradeModal(true);
      } else if (error.message.includes('not connected') || error.message.includes('Connect your')) {
        setShowConnectionModal(true);
      } else {
        toast({
          title: "Posting Failed",
          description: error.message || "Failed to post content",
          variant: "destructive",
        });
      }
    },
  });

  const handleGenerateSchedule = () => {
    if (quotaStatus && quotaStatus.usedPosts >= quotaStatus.quota) {
      setShowUpgradeModal(true);
      return;
    }
    generateScheduleMutation.mutate();
  };

  const handleApprovePost = (postId: string) => {
    if (quotaStatus && quotaStatus.usedPosts >= quotaStatus.quota) {
      setShowUpgradeModal(true);
      return;
    }
    approvePostMutation.mutate(postId);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-AU', {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getDaysRemaining = () => {
    if (!quotaStatus?.periodStart) return 0;
    const periodStart = new Date(quotaStatus.periodStart);
    const periodEnd = new Date(periodStart.getTime() + (30 * 24 * 60 * 60 * 1000));
    const now = new Date();
    const remaining = Math.max(0, Math.ceil((periodEnd.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)));
    return remaining;
  };

  if (quotaLoading) {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Calendar className="h-5 w-5" />
              Loading Schedule...
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="animate-pulse space-y-4">
              <div className="h-4 bg-gray-200 rounded w-3/4"></div>
              <div className="h-4 bg-gray-200 rounded w-1/2"></div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!quotaStatus) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-600">
            <AlertTriangle className="h-5 w-5" />
            Quota Information Unavailable
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p>Unable to load subscription quota information. Please refresh the page.</p>
        </CardContent>
      </Card>
    );
  }

  const posts = scheduleData?.posts || [];
  const draftPosts = posts.filter(p => p.status === 'draft');
  const postedPosts = posts.filter(p => p.status === 'posted' && p.isCounted);
  const quotaPercentage = (quotaStatus.usedPosts / quotaStatus.quota) * 100;
  const daysRemaining = getDaysRemaining();

  return (
    <div className="space-y-6">
      {/* Quota Status Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Calendar className="h-5 w-5" />
              Subscription Quota
            </div>
            <Badge variant={quotaStatus.canPost ? "default" : "destructive"}>
              {quotaStatus.subscriptionTier.toUpperCase()}
            </Badge>
          </CardTitle>
          <CardDescription>
            30-day rolling period • {daysRemaining} days remaining
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Posts Used</span>
              <span>{quotaStatus.usedPosts} of {quotaStatus.quota}</span>
            </div>
            <Progress value={quotaPercentage} className="h-2" />
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>{quotaStatus.remainingPosts} remaining</span>
              <span>{quotaStatus.draftCount} drafts ready</span>
            </div>
          </div>

          {quotaStatus.lastPosted && (
            <div className="text-sm text-muted-foreground">
              Last posted: {formatDate(quotaStatus.lastPosted)}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Action Buttons */}
      <div className="flex gap-4">
        <Button
          onClick={handleGenerateSchedule}
          disabled={generateScheduleMutation.isPending || quotaStatus.usedPosts >= quotaStatus.quota}
          className="flex items-center gap-2"
        >
          <RefreshCw className={`h-4 w-4 ${generateScheduleMutation.isPending ? 'animate-spin' : ''}`} />
          {posts.length > 0 ? 'Regenerate Schedule' : 'Generate Schedule'}
        </Button>

        {quotaStatus.usedPosts >= quotaStatus.quota && (
          <Button
            variant="outline"
            onClick={() => setShowUpgradeModal(true)}
            className="flex items-center gap-2"
          >
            <AlertTriangle className="h-4 w-4" />
            Upgrade Plan
          </Button>
        )}
      </div>

      {/* Posts Grid */}
      {posts.length > 0 && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Content Schedule</h3>
            <div className="flex gap-4 text-sm text-muted-foreground">
              <span>{postedPosts.length} posted</span>
              <span>{draftPosts.length} drafts</span>
            </div>
          </div>

          <div className="grid gap-4">
            {posts
              .sort((a, b) => new Date(a.scheduledAt).getTime() - new Date(b.scheduledAt).getTime())
              .map((post) => (
                <Card key={post.postId} className={`transition-all ${
                  post.status === 'posted' ? 'border-green-200 bg-green-50/50' : 'border-gray-200'
                }`}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 space-y-3">
                        <div className="flex items-center gap-3">
                          <div className={`w-8 h-8 rounded-full ${platformColors[post.platform]} flex items-center justify-center text-white text-sm`}>
                            {platformIcons[post.platform]}
                          </div>
                          <div>
                            <div className="font-medium capitalize">{post.platform}</div>
                            <div className="text-sm text-muted-foreground">
                              {formatDate(post.scheduledAt)}
                            </div>
                          </div>
                          <Badge variant={post.status === 'posted' ? 'default' : 'secondary'}>
                            {post.status === 'posted' ? (
                              <CheckCircle className="w-3 h-3 mr-1" />
                            ) : (
                              <Clock className="w-3 h-3 mr-1" />
                            )}
                            {post.status}
                          </Badge>
                        </div>

                        <div className="text-sm line-clamp-3">
                          {post.content}
                        </div>
                      </div>

                      <div className="flex flex-col gap-2">
                        {post.status === 'draft' && (
                          <Button
                            size="sm"
                            onClick={() => handleApprovePost(post.postId)}
                            disabled={
                              approvePostMutation.isPending || 
                              quotaStatus.usedPosts >= quotaStatus.quota
                            }
                            className="flex items-center gap-1"
                          >
                            <Send className="h-3 w-3" />
                            {approvePostMutation.isPending ? 'Posting...' : 'Approve & Post'}
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
          </div>
        </div>
      )}

      {/* Upgrade Modal */}
      <Dialog open={showUpgradeModal} onOpenChange={setShowUpgradeModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Post Quota Reached</DialogTitle>
            <DialogDescription>
              You've reached your post limit for this 30-day cycle. Upgrade your plan to continue posting.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="text-sm">
              <p><strong>Current Plan:</strong> {quotaStatus.subscriptionTier.charAt(0).toUpperCase() + quotaStatus.subscriptionTier.slice(1)} ({quotaStatus.quota} posts/month)</p>
              <p><strong>Posts Used:</strong> {quotaStatus.usedPosts} of {quotaStatus.quota}</p>
              <p><strong>Cycle Resets:</strong> {daysRemaining} days</p>
            </div>
            
            <div className="space-y-2">
              <h4 className="font-medium">Available Plans:</h4>
              <ul className="text-sm space-y-1">
                <li>• <strong>Starter:</strong> 10 posts/month - $19.99</li>
                <li>• <strong>Growth:</strong> 20 posts/month - $41.99</li>
                <li>• <strong>Professional:</strong> 30 posts/month - $99.99</li>
              </ul>
            </div>

            <div className="flex gap-2 pt-4">
              <Button onClick={() => setShowUpgradeModal(false)} variant="outline">
                Continue with Current Plan
              </Button>
              <Button onClick={() => {
                setShowUpgradeModal(false);
                // Navigate to pricing or upgrade page
                window.open('/pricing', '_blank');
              }}>
                Upgrade Plan
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Platform Connection Modal */}
      <Dialog open={showConnectionModal} onOpenChange={setShowConnectionModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Connect Your Social Media Account</DialogTitle>
            <DialogDescription>
              You need to connect your social media accounts to post content. Connect at least one platform to continue.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="text-sm">
              <p>Available platforms to connect:</p>
              <ul className="mt-2 space-y-1">
                <li>• Facebook - Connect your Facebook page</li>
                <li>• Instagram - Connect your Instagram business account</li>
                <li>• LinkedIn - Connect your LinkedIn profile</li>
                <li>• X (Twitter) - Connect your X account</li>
                <li>• YouTube - Connect your YouTube channel</li>
              </ul>
            </div>

            <div className="flex gap-2 pt-4">
              <Button onClick={() => setShowConnectionModal(false)} variant="outline">
                Cancel
              </Button>
              <Button onClick={() => {
                setShowConnectionModal(false);
                window.location.href = '/platform-connections';
              }}>
                Connect Platforms
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}