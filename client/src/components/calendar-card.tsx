import { Calendar, Clock } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { SiFacebook, SiInstagram, SiLinkedin, SiX, SiYoutube } from "react-icons/si";

interface ScheduledPost {
  id: number;
  platform: string;
  content: string;
  scheduledFor: string;
  status: string;
  strategicTheme?: string;
  businessCanvasPhase?: string;
  engagementOptimisation?: string;
}

interface CalendarCardProps {
  date: Date;
  posts: ScheduledPost[];
  events?: {
    name: string;
    type: string;
    impact: string;
  }[];
}

const platformIcons = {
  facebook: SiFacebook,
  instagram: SiInstagram,
  linkedin: SiLinkedin,
  x: SiX,
  youtube: SiYoutube,
};

const platformColours = {
  facebook: "text-blue-600",
  instagram: "text-pink-500",
  linkedin: "text-blue-700",
  x: "text-gray-900",
  youtube: "text-red-600",
};

export default function CalendarCard({ date, posts, events = [] }: CalendarCardProps) {
  const formatDate = (date: Date) => {
    return date.toLocaleDateString('en-AU', {
      weekday: 'short',
      day: 'numeric',
      month: 'short'
    });
  };

  const formatTime = (dateString: string) => {
    return new Date(dateString).toLocaleTimeString('en-AU', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true
    });
  };

  const isToday = (date: Date) => {
    const today = new Date();
    return date.toDateString() === today.toDateString();
  };

  const isPast = (date: Date) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return date < today;
  };

  const getPostsByTime = () => {
    return posts
      .sort((a, b) => new Date(a.scheduledFor).getTime() - new Date(b.scheduledFor).getTime())
      .reduce((acc, post) => {
        const time = formatTime(post.scheduledFor);
        if (!acc[time]) acc[time] = [];
        acc[time].push(post);
        return acc;
      }, {} as Record<string, ScheduledPost[]>);
  };

  const postsByTime = getPostsByTime();
  const hasHighImpactEvent = events.some(event => event.impact === 'high');

  return (
    <Card className={`
      transition-all duration-200 hover:shadow-md
      ${isToday(date) ? 'ring-2 ring-blue-500 bg-blue-50' : ''}
      ${isPast(date) ? 'opacity-75' : ''}
      ${hasHighImpactEvent ? 'border-amber-300 bg-amber-50' : ''}
    `}>
      <CardContent className="p-3">
        {/* Date Header */}
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-2">
            <Calendar className="w-4 h-4 text-gray-500" />
            <span className={`text-sm font-medium ${isToday(date) ? 'text-blue-700' : 'text-gray-700'}`}>
              {formatDate(date)}
            </span>
          </div>
          {posts.length > 0 && (
            <div className="bg-indigo-100 text-indigo-700 text-xs px-2 py-1 rounded-full font-medium">
              {posts.length} post{posts.length > 1 ? 's' : ''}
            </div>
          )}
        </div>

        {/* Queensland Events */}
        {events.length > 0 && (
          <div className="mb-3">
            {events.map((event, index) => (
              <div key={index} className={`
                text-xs p-2 rounded-md mb-1
                ${event.impact === 'high' ? 'bg-amber-100 text-amber-800 border border-amber-200' : 
                  event.impact === 'medium' ? 'bg-yellow-100 text-yellow-800' : 
                  'bg-gray-100 text-gray-700'}
              `}>
                <div className="font-medium">{event.name}</div>
                <div className="text-xs opacity-75 capitalize">{event.type} • {event.impact} impact</div>
              </div>
            ))}
          </div>
        )}

        {/* Scheduled Posts */}
        {posts.length > 0 ? (
          <div className="space-y-2">
            {Object.entries(postsByTime).map(([time, timePosts]) => (
              <div key={time} className="border-l-2 border-gray-200 pl-3">
                <div className="flex items-center space-x-1 mb-1">
                  <Clock className="w-3 h-3 text-gray-400" />
                  <span className="text-xs text-gray-600 font-medium">{time}</span>
                </div>
                <div className="space-y-2">
                  {timePosts.map((post) => {
                    const IconComponent = platformIcons[post.platform as keyof typeof platformIcons];
                    const colorClass = platformColours[post.platform as keyof typeof platformColours];
                    
                    return (
                      <div
                        key={post.id}
                        className={`
                          px-3 py-2 rounded-md text-xs w-full
                          bg-white border shadow-sm hover:shadow-md transition-shadow
                          ${post.status === 'published' ? 'bg-green-50 border-green-200' : ''}
                          ${post.status === 'failed' ? 'bg-red-50 border-red-200' : ''}
                        `}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-1">
                            {IconComponent && (
                              <IconComponent className={`w-3 h-3 ${colorClass}`} />
                            )}
                            <span className="capitalize text-gray-700 font-medium">
                              {post.platform}
                            </span>
                          </div>
                          {/* Strategic Media Planning Info */}
                          {post.strategicTheme && (
                            <div className="text-xs text-purple-700 font-bold bg-purple-100 px-2 py-1 rounded-full border border-purple-300">
                              ✨ Strategic
                            </div>
                          )}
                        </div>
                        
                        {/* Strategic Reason Display */}
                        {post.strategicTheme && (
                          <div className="mb-2 p-2 bg-purple-50 rounded-md border-l-4 border-purple-400">
                            <div className="text-xs font-medium text-purple-700 mb-1">Media Planning Strategy:</div>
                            <div className="text-xs text-purple-600">
                              <strong>Strategic Theme:</strong> {post.strategicTheme.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </div>
                            {post.businessCanvasPhase && (
                              <div className="text-xs text-purple-600">
                                <strong>Business Phase:</strong> {post.businessCanvasPhase}
                              </div>
                            )}
                            {post.engagementOptimisation && (
                              <div className="text-xs text-purple-600">
                                <strong>ROI Potential:</strong> {post.engagementOptimisation}
                              </div>
                            )}
                          </div>
                        )}
                        {/* Content hidden in calendar - strategic planning info shown above */}
                        <div className="text-xs text-gray-500 italic">
                          Click post to view full content
                        </div>
                        {post.status === 'published' && (
                          <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                        )}
                        {post.status === 'failed' && (
                          <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                        )}
                        {post.status === 'scheduled' && (
                          <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-4">
            <div className="text-gray-400 text-xs">No posts scheduled</div>
          </div>
        )}

        {/* Post Status Summary */}
        {posts.length > 0 && (
          <div className="mt-3 pt-2 border-t border-gray-100">
            <div className="flex justify-between text-xs">
              <div className="flex items-center space-x-1">
                <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                <span className="text-gray-600">
                  {posts.filter(p => p.status === 'scheduled').length} scheduled
                </span>
              </div>
              <div className="flex items-center space-x-1">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-gray-600">
                  {posts.filter(p => p.status === 'published').length} published
                </span>
              </div>
              {posts.some(p => p.status === 'failed') && (
                <div className="flex items-center space-x-1">
                  <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                  <span className="text-gray-600">
                    {posts.filter(p => p.status === 'failed').length} failed
                  </span>
                </div>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}