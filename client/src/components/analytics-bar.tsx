import { useEffect, useState } from "react";
import { TrendingUp, Eye, Users, Target } from "lucide-react";
import { SiFacebook, SiInstagram, SiLinkedin, SiYoutube, SiX } from "react-icons/si";
import { cn } from "@/lib/utils";
import { MetaPixelTracker } from "@/lib/meta-pixel";

interface AnalyticsData {
  totalPosts: number;
  totalReach: number;
  totalEngagement: number;
  averageReach: number;
  connectedPlatforms: string[];
  topPerformingPost: {
    content: string;
    reach: number;
    platform: string;
  };
}

interface AnalyticsBarProps {
  className?: string;
}

const getPlatformIcon = (platform: string) => {
  const iconProps = { className: "w-4 h-4" };
  
  switch (platform.toLowerCase()) {
    case 'facebook':
      return <SiFacebook {...iconProps} style={{ color: '#1877F2' }} />;
    case 'instagram':
      return <SiInstagram {...iconProps} style={{ color: '#E4405F' }} />;
    case 'linkedin':
      return <SiLinkedin {...iconProps} style={{ color: '#0A66C2' }} />;
    case 'youtube':
      return <SiYoutube {...iconProps} style={{ color: '#FF0000' }} />;
    case 'x':
      return <SiX {...iconProps} style={{ color: '#000000' }} />;
    default:
      return null;
  }
};

export default function AnalyticsBar({ className }: AnalyticsBarProps) {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        // Temporarily disable analytics API calls to prevent auth loop
        setLoading(false);
        
        // Track analytics bar view for engagement insights
        MetaPixelTracker.trackFeatureUsage('analytics_bar_view');
        
        return;
        const response = await fetch('/api/analytics/monthly');
        if (response.ok) {
          const data = await response.json();
          setAnalytics(data);
          
          // Track analytics bar data load with performance metrics
          MetaPixelTracker.trackCustomEvent('AnalyticsBarLoaded', {
            total_posts: data.totalPosts,
            total_reach: data.totalReach,
            total_engagement: data.totalEngagement,
            connected_platforms_count: data.connectedPlatforms?.length || 0,
            has_top_performing_post: !!data.topPerformingPost
          });
        }
      } catch (error) {
        console.error('Error fetching analytics:', error);
        
        // Track analytics loading errors
        MetaPixelTracker.trackError('analytics_bar_load_failed', (error as Error).message, {
          component: 'analytics_bar',
          retry_attempt: 'initial'
        });
      } finally {
        setLoading(false);
      }
    };

    fetchAnalytics();
    
    // Update every 5 minutes
    const interval = setInterval(fetchAnalytics, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className={cn("bg-gradient-to-r from-blue-50 to-purple-50 border-b border-border", className)}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3">
          <div className="flex items-center justify-center">
            <div className="animate-pulse flex space-x-8">
              <div className="h-4 bg-gray-300 rounded w-32"></div>
              <div className="h-4 bg-gray-300 rounded w-24"></div>
              <div className="h-4 bg-gray-300 rounded w-28"></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!analytics) {
    return (
      <div className={cn("bg-gradient-to-r from-blue-50 to-purple-50 border-b border-border", className)}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3">
          <div className="flex items-center justify-center text-sm text-gray-600">
            <Target className="w-4 h-4 mr-2" />
            Analytics data will appear once posts are published
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={cn("bg-gradient-to-r from-blue-50 to-purple-50 border-b border-border", className)}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-8">
            <div className="flex items-center text-sm">
              <TrendingUp className="w-4 h-4 text-[#3250fa] mr-2" />
              <span className="font-semibold text-gray-900">{analytics.totalPosts}</span>
              <span className="text-gray-600 ml-1">posts this month</span>
            </div>
            
            <div className="flex items-center text-sm">
              <Eye className="w-4 h-4 text-blue-600 mr-2" />
              <span className="font-semibold text-gray-900">{analytics.totalReach.toLocaleString()}</span>
              <span className="text-gray-600 ml-1">total reach</span>
            </div>
            
            <div className="flex items-center text-sm">
              <Users className="w-4 h-4 text-purple-600 mr-2" />
              <span className="font-semibold text-gray-900">{analytics.totalEngagement.toLocaleString()}</span>
              <span className="text-gray-600 ml-1">engagements</span>
            </div>
            
            <div className="flex items-center text-sm">
              <Target className="w-4 h-4 text-orange-600 mr-2" />
              <span className="font-semibold text-gray-900">{analytics.averageReach.toLocaleString()}</span>
              <span className="text-gray-600 ml-1">avg reach</span>
            </div>
            
            {analytics.connectedPlatforms && analytics.connectedPlatforms.length > 0 && (
              <div className="flex items-center space-x-2">
                {analytics.connectedPlatforms.map((platform, index) => (
                  <div key={index} className="p-1">
                    {getPlatformIcon(platform)}
                  </div>
                ))}
              </div>
            )}
          </div>
          
          {analytics.topPerformingPost && (
            <div className="hidden md:flex items-center text-sm bg-white/60 rounded-lg px-3 py-1.5">
              <span className="text-gray-600">Top post:</span>
              <span className="font-medium text-gray-900 ml-1 max-w-48 truncate">
                {analytics.topPerformingPost.content}
              </span>
              <span className="text-[#3250fa] ml-2 font-semibold">
                {analytics.topPerformingPost.reach.toLocaleString()} reach
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}