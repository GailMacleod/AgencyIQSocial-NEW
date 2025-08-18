import { Badge } from "@/components/ui/badge";
import { Circle, CheckCircle, Clock, AlertCircle } from "lucide-react";

export type PostStatus = 'draft' | 'approved' | 'published' | 'failed';

interface StatusIndicatorProps {
  status: PostStatus;
  size?: 'sm' | 'md' | 'lg';
  showText?: boolean;
}

export function StatusIndicator({ status, size = 'md', showText = true }: StatusIndicatorProps) {
  const statusConfig = {
    draft: {
      icon: Circle,
      color: 'bg-gray-100 text-gray-800 border-gray-300',
      text: 'Draft',
      dotColor: 'text-gray-400'
    },
    approved: {
      icon: Clock,
      color: 'bg-yellow-100 text-yellow-800 border-yellow-300',
      text: 'Approved',
      dotColor: 'text-yellow-500'
    },
    published: {
      icon: CheckCircle,
      color: 'bg-green-100 text-green-800 border-green-300',
      text: 'Published',
      dotColor: 'text-green-500'
    },
    failed: {
      icon: AlertCircle,
      color: 'bg-red-100 text-red-800 border-red-300',
      text: 'Failed',
      dotColor: 'text-red-500'
    }
  };

  const config = statusConfig[status];
  const IconComponent = config.icon;

  const sizeClasses = {
    sm: 'text-xs px-2 py-1',
    md: 'text-sm px-3 py-1',
    lg: 'text-base px-4 py-2'
  };

  const iconSizes = {
    sm: 'w-3 h-3',
    md: 'w-4 h-4',
    lg: 'w-5 h-5'
  };

  if (!showText) {
    return (
      <div className="flex items-center">
        <IconComponent className={`${iconSizes[size]} ${config.dotColor}`} />
      </div>
    );
  }

  return (
    <Badge variant="outline" className={`${config.color} ${sizeClasses[size]} border flex items-center space-x-1`}>
      <IconComponent className={`${iconSizes[size]} ${config.dotColor}`} />
      <span className="font-medium">{config.text}</span>
    </Badge>
  );
}

// Platform-specific status indicator
export function PlatformStatusIndicator({ 
  platform, 
  connected, 
  health 
}: { 
  platform: string; 
  connected: boolean; 
  health: 'healthy' | 'warning' | 'error' 
}) {
  const platformIcons = {
    facebook: '📘',
    instagram: '📷',
    linkedin: '💼',
    youtube: '📺',
    twitter: '🐦'
  };

  const healthColors = {
    healthy: 'bg-green-100 text-green-800',
    warning: 'bg-yellow-100 text-yellow-800',
    error: 'bg-red-100 text-red-800'
  };

  return (
    <div className="flex items-center space-x-2">
      <span className="text-lg">
        {platformIcons[platform as keyof typeof platformIcons] || '📱'}
      </span>
      <Badge 
        variant="outline" 
        className={`${connected ? healthColors[health] : 'bg-gray-100 text-gray-800'} text-xs`}
      >
        {connected ? health : 'disconnected'}
      </Badge>
    </div>
  );
}

// Progress indicator for content generation
export function GenerationProgressIndicator({ 
  stage, 
  progress 
}: { 
  stage: string; 
  progress: number 
}) {
  return (
    <div className="flex items-center space-x-3">
      <div className="flex-1">
        <div className="flex items-center justify-between mb-1">
          <span className="text-sm font-medium text-gray-700">{stage}</span>
          <span className="text-sm text-gray-500">{progress}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div 
            className="bg-purple-600 h-2 rounded-full transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>
    </div>
  );
}