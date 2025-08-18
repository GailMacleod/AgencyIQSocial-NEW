import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { 
  Calendar, 
  Clock, 
  CheckCircle, 
  XCircle, 
  Edit3, 
  Save, 
  X,
  Eye,
  ThumbsUp,
  Play
} from 'lucide-react';
import { format } from 'date-fns';
import { Post } from '@/types';

interface PostCardProps {
  post: Post;
  onApprove?: (postId: number) => void;
  onEdit?: (postId: number, content: string) => void;
  onRegenerate?: (postId: number) => void;
  onPreview?: (postId: number) => void;
  isEditing?: boolean;
  onEditStart?: (postId: number) => void;
  onEditCancel?: () => void;
  className?: string;
}

export function PostCard({
  post,
  onApprove,
  onEdit,
  onRegenerate,
  onPreview,
  isEditing,
  onEditStart,
  onEditCancel,
  className = ''
}: PostCardProps): JSX.Element {
  const [editedContent, setEditedContent] = useState(post.content);

  const handleSave = (): void => {
    onEdit?.(post.id, editedContent);
  };

  const handleCancel = (): void => {
    setEditedContent(post.content);
    onEditCancel?.();
  };

  const getPlatformColour = (platform: string): string => {
    const colours = {
      facebook: 'bg-blue-500',
      instagram: 'bg-pink-500',
      linkedin: 'bg-blue-700',
      youtube: 'bg-red-500',
      x: 'bg-black',
    };
    return colours[platform as keyof typeof colours] || 'bg-gray-500';
  };

  const getStatusColour = (status: string): string => {
    const colours = {
      draft: 'bg-gray-100 text-gray-800',
      approved: 'bg-green-100 text-green-800',
      published: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
    };
    return colours[status as keyof typeof colours] || 'bg-gray-100 text-gray-800';
  };

  return (
    <Card className={`${className} transition-all hover:shadow-md`}>
      <CardContent className="p-4">
        <div className="space-y-3">
          {/* Header */}
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${getPlatformColour(post.platform)}`} />
              <span className="font-medium capitalize">{post.platform}</span>
              <Badge variant="outline" className={getStatusColour(post.status)}>
                {post.status}
              </Badge>
            </div>
            
            <div className="flex items-center gap-1">
              {post.status === 'draft' && (
                <>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => onEditStart?.(post.id)}
                    className="h-8 w-8 p-0"
                  >
                    <Edit3 className="w-4 h-4" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => onPreview?.(post.id)}
                    className="h-8 w-8 p-0"
                  >
                    <Eye className="w-4 h-4" />
                  </Button>
                </>
              )}
              
              {post.status === 'approved' && post.hasVideo && (
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-8 w-8 p-0"
                >
                  <Play className="w-4 h-4" />
                </Button>
              )}
            </div>
          </div>

          {/* Content */}
          <div className="space-y-2">
            {isEditing ? (
              <div className="space-y-2">
                <Textarea
                  value={editedContent}
                  onChange={(e) => setEditedContent(e.target.value)}
                  className="min-h-[100px] resize-none"
                  placeholder="Edit your post content..."
                />
                <div className="flex gap-2">
                  <Button size="sm" onClick={handleSave} className="h-8">
                    <Save className="w-4 h-4 mr-1" />
                    Save
                  </Button>
                  <Button size="sm" variant="outline" onClick={handleCancel} className="h-8">
                    <X className="w-4 h-4 mr-1" />
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <p className="text-sm text-gray-700 leading-relaxed line-clamp-4">
                {post.content}
              </p>
            )}
          </div>

          {/* Schedule Info */}
          <div className="flex items-center gap-4 text-xs text-gray-500">
            <div className="flex items-center gap-1">
              <Calendar className="w-3 h-3" />
              <span>{format(new Date(post.scheduledFor), 'MMM d, yyyy')}</span>
            </div>
            <div className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              <span>{format(new Date(post.scheduledFor), 'h:mm a')}</span>
            </div>
          </div>

          {/* Local Event */}
          {post.localEvent && (
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-2">
              <p className="text-xs text-purple-800 font-medium">
                📅 {post.localEvent}
              </p>
            </div>
          )}

          {/* AI Recommendation */}
          {post.aiRecommendation && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-2">
              <p className="text-xs text-blue-800">
                🤖 {post.aiRecommendation}
              </p>
            </div>
          )}

          {/* Analytics */}
          {post.analytics && (
            <div className="bg-gray-50 rounded-lg p-2 grid grid-cols-3 gap-2">
              <div className="text-center">
                <div className="text-sm font-medium">{post.analytics.reach.toLocaleString()}</div>
                <div className="text-xs text-gray-600">Reach</div>
              </div>
              <div className="text-center">
                <div className="text-sm font-medium">{post.analytics.engagement}%</div>
                <div className="text-xs text-gray-600">Engagement</div>
              </div>
              <div className="text-center">
                <div className="text-sm font-medium">{post.analytics.impressions.toLocaleString()}</div>
                <div className="text-xs text-gray-600">Impressions</div>
              </div>
            </div>
          )}

          {/* Actions */}
          {post.status === 'draft' && !isEditing && (
            <div className="flex gap-2 pt-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => onEditStart?.(post.id)}
                className="h-8"
              >
                <Edit3 className="w-4 h-4 mr-1" />
                Edit
              </Button>
              <Button
                size="sm"
                onClick={() => onApprove?.(post.id)}
                className="flex-1 h-8"
              >
                <ThumbsUp className="w-4 h-4 mr-1" />
                Approve & Queue
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => onRegenerate?.(post.id)}
                className="h-8"
              >
                <XCircle className="w-4 h-4 mr-1" />
                Regenerate
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}