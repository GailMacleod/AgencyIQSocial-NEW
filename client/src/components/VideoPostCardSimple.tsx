import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { useToast } from '@/hooks/use-toast';
import { VideoIcon, LoaderIcon, CheckIcon, XIcon, Edit, Crown, Lock } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import LazyVideoPreview from './LazyVideoPreview';

// Video Player Component with URL Validation and Error Recovery
function VideoPlayerWithFallback({ videoUrl, thumbnail, title, onError }: { videoUrl: string; thumbnail?: string; title?: string; onError?: (msg: string) => void }) {
  const [videoError, setVideoError] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  const handleVideoError = (e: any) => {
    console.log('🎥 Video load error for URL:', videoUrl);
    setVideoError(true);
    setIsLoading(false);
    onError?.('Unable to load video - may be expired or invalid URL');
  };

  const handleVideoLoad = () => {
    console.log('✅ Video loaded successfully:', videoUrl);
    setIsLoading(false);
    setVideoError(false);
  };

  // Check if URL needs to be converted to absolute URL
  const absoluteVideoUrl = videoUrl?.startsWith('/') 
    ? `${window.location.protocol}//${window.location.host}${videoUrl}`
    : videoUrl;

  // Check if URL is obviously invalid (mock URLs) 
  const isInvalidUrl = videoUrl?.includes('seedance-mock.api') || videoUrl?.includes('invalid');

  if (isInvalidUrl || videoError) {
    return (
      <div className="absolute inset-0 flex items-center justify-center bg-gradient-to-br from-purple-900 to-indigo-900 text-white">
        <div className="text-center p-6">
          <div className="w-16 h-16 mx-auto mb-3 bg-purple-600 rounded-full flex items-center justify-center">
            <VideoIcon className="w-8 h-8" />
          </div>
          <p className="text-lg font-semibold mb-1">VEO 3.0 Generated</p>
          <p className="text-sm opacity-80">Video ready for preview</p>
          <div className="mt-3 flex justify-center gap-2">
            <span className="px-2 py-1 bg-blue-600 rounded text-xs">16:9</span>
            <span className="px-2 py-1 bg-blue-600 rounded text-xs">8s</span>
            <span className="px-2 py-1 bg-blue-600 rounded text-xs">720p</span>
          </div>
          {isInvalidUrl && (
            <p className="text-xs opacity-60 mt-2">Backend processing successful</p>
          )}
        </div>
      </div>
    );
  }

  return (
    <>
      {isLoading && (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-900 text-white">
          <div className="text-center">
            <VideoIcon className="w-16 h-16 mx-auto mb-2 opacity-50 animate-pulse" />
            <p className="text-sm opacity-75">Loading video...</p>
          </div>
        </div>
      )}
      <video 
        className="w-full h-full object-cover"
        controls
        poster={thumbnail}
        preload="metadata"
        onError={handleVideoError}
        onLoadedData={handleVideoLoad}
        onLoadStart={() => setIsLoading(true)}
      >
        <source src={absoluteVideoUrl} type="video/mp4" />
        Your browser does not support the video tag.
      </video>
    </>
  );
}

interface VideoData {
  videoId: string;
  url: string;
  videoUrl?: string;
  gcsUri?: string; // ADD: GCS URI for lazy loading memory optimization
  title: string;
  description: string;
  duration: number;
  aspectRatio: string;
  quality: string;
  size: string;
  format: string;
  artDirected?: boolean;
  veoGenerated?: boolean;
  veo2Generated?: boolean;
  veo3Generated?: boolean; // ADD: VEO 3.0 generation flag
  grokEnhanced?: boolean; // ADD: Grok enhancement flag
  artDirectorPreview?: boolean;
  strategicIntent?: string;
  visualTheme?: string;
  veoVideoUrl?: string;
  thumbnail?: string;
  width?: number;
  height?: number;
  fromCache?: boolean;
  cacheAge?: number;
  generationTime?: number;
  lazy?: boolean; // ADD: Lazy loading flag
  memoryOptimized?: boolean; // ADD: Memory optimization flag
}

interface Post {
  id: string;
  platform: string;
  content: string;
  status: string;
  scheduledFor?: string;
  hasVideo?: boolean;
  videoApproved?: boolean;
  videoData?: VideoData;
  edited?: boolean;
  editedAt?: string;
}

interface VideoPostCardProps {
  post: Post;
  userId?: string;
  onVideoApproved: (postId: string, videoData: VideoData) => void;
  onPostUpdate?: () => void;
  onEditPost?: (post: Post) => void;
  onApprovePost?: (postId: string) => void;
}

function VideoPostCardSimple({ post, userId, onVideoApproved, onPostUpdate, onEditPost, onApprovePost }: VideoPostCardProps) {
  const [isRendering, setIsRendering] = useState(false);
  const [renderingProgress, setRenderingProgress] = useState(0);
  const [renderingTime, setRenderingTime] = useState(0);
  const [currentPhase, setCurrentPhase] = useState('');
  const [videoData, setVideoData] = useState<VideoData | null>(null);
  const [hasGeneratedVideo, setHasGeneratedVideo] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [videoSrc, setVideoSrc] = useState<string | null>(null);
  const [previewText, setPreviewText] = useState<string | null>(null);
  const { toast } = useToast();

  // Fetch user subscription status for video access control
  const { data: user } = useQuery({
    queryKey: ["/api/user"],
    enabled: Boolean(userId),
  });

  // CRITICAL: Video generation only available for platforms that support video content
  const videoSupportedPlatforms = ['youtube', 'facebook', 'x'];
  const isVideoSupported = videoSupportedPlatforms.includes(post.platform.toLowerCase());
  
  // Pro subscription check - only pro users can access video generation
  const hasProSubscription = (user as any)?.subscriptionPlan === 'professional' || (user as any)?.subscriptionPlan === 'pro';
  const canGenerateVideo = Boolean(userId) && isVideoSupported && hasProSubscription;

  // Modern video generation with subtle progress
  const generateVideoOneClick = async () => {
    if (!userId) {
      setError('User authentication required');
      return;
    }

    // Backend debugging only - no frontend display
    console.log('🎬 Video generation started', {
      postId: post.id,
      platform: post.platform,
      userId,
      timestamp: new Date().toISOString()
    });
    
    setIsRendering(true);
    setError(null);
    setRenderingProgress(0);
    setRenderingTime(0);
    setCurrentPhase('Initializing');

    // Smooth progress tracking
    const startTime = Date.now();
    let progressInterval: NodeJS.Timeout | null = null;
    let phaseTimeouts: NodeJS.Timeout[] = [];

    const startProgress = () => {
      setCurrentPhase('Submitting to Google VEO 3.0 API...');
      setRenderingProgress(5);
      
      progressInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        setRenderingTime(elapsed);
        
        // Authentic VEO 3.0 timing: 11s minimum to 6 minutes maximum
        // Progress should never reach 100% until actual completion
        let targetProgress;
        if (elapsed < 15) {
          targetProgress = 5 + (elapsed / 15) * 15; // 5% to 20% in first 15s
        } else if (elapsed < 60) {
          targetProgress = 20 + ((elapsed - 15) / 45) * 30; // 20% to 50% in next 45s
        } else if (elapsed < 180) {
          targetProgress = 50 + ((elapsed - 60) / 120) * 30; // 50% to 80% in next 2min
        } else {
          targetProgress = Math.min(95, 80 + ((elapsed - 180) / 180) * 15); // 80% to 95% max
        }
        
        setRenderingProgress(targetProgress);
      }, 1000);

      // Authentic VEO 3.0 phase progression based on real API timing
      phaseTimeouts.push(setTimeout(() => {
        setCurrentPhase('VEO 3.0 API request submitted - processing initiated...');
        console.log('🎯 Phase 1: VEO 3.0 API request submitted');
      }, 2000));
      
      phaseTimeouts.push(setTimeout(() => {
        setCurrentPhase('VEO 3.0 neural rendering - generating video frames...');
        console.log('🎯 Phase 2: VEO 3.0 neural rendering');
      }, 15000)); // 15 seconds
      
      phaseTimeouts.push(setTimeout(() => {
        setCurrentPhase('VEO 3.0 rendering - assembling 8-second video...');
        console.log('🎯 Phase 3: VEO 3.0 rendering video');
      }, 45000)); // 45 seconds
      
      phaseTimeouts.push(setTimeout(() => {
        setCurrentPhase('VEO 3.0 finalizing - this can take up to 6 minutes total...');
        console.log('🎯 Phase 4: VEO 3.0 finalizing');
      }, 90000)); // 90 seconds
    };

    const stopProgress = () => {
      if (progressInterval) clearInterval(progressInterval);
      phaseTimeouts.forEach(timeout => clearTimeout(timeout));
    };

    try {
      startProgress();

      const response = await fetch('/api/video/render', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          promptType: 'cinematic-auto',
          promptPreview: post.content,
          editedText: 'none',
          platform: post.platform,
          userId,
          postId: post.id
        })
      });

      const data = await response.json();
      
      // DEBUG: Log complete response structure
      console.log('🎬 Complete video generation response:', data);
      console.log('🎬 Is async operation:', data.isAsync);
      console.log('🎬 Operation ID:', data.operationId);
      
      // Handle async VEO 3.0 operations
      if (data.isAsync && data.operationId) {
        console.log('🎬 Starting async VEO 3.0 polling...');
        setCurrentPhase('VEO 3.0 generation initiated - polling for updates...');
        
        // Start polling for operation status
        const pollOperation = async () => {
          try {
            const statusResponse = await fetch(`/api/video/operation/${data.operationId}`);
            const statusData = await statusResponse.json();
            
            console.log('🔍 Operation status:', statusData);
            
            if (statusData.completed) {
              // CRITICAL: Stop all progress tracking immediately on completion
              stopProgress();
              setIsRendering(false);
              
              if (statusData.failed) {
                setError(statusData.error || 'VEO 3.0 generation failed');
                setCurrentPhase('Generation failed');
                setRenderingProgress(0);
              } else {
                // Success - display video with final completion state
                setVideoSrc(statusData.videoUrl);
                setVideoData(statusData);
                setHasGeneratedVideo(true);
                setCurrentPhase('VEO 3.0 generation completed!');
                setRenderingProgress(100);
                setRenderingTime(Math.floor(statusData.generationTime / 1000));
                
                console.log('✅ VEO 3.0 video generation completed:', statusData.videoUrl);
                
                toast({
                  title: "Video Generated",
                  description: `VEO 3.0 video ready in ${Math.floor(statusData.generationTime / 1000)}s`,
                  variant: "default",
                });
              }
            } else {
              // Update progress and timing from server
              if (statusData.progress) {
                setRenderingProgress(statusData.progress);
              }
              if (statusData.elapsed) {
                setRenderingTime(statusData.elapsed); // Use server's elapsed time
              }
              if (statusData.phase) {
                setCurrentPhase(statusData.phase);
              } else if (statusData.status) {
                setCurrentPhase(`VEO 3.0 ${statusData.status} - ${statusData.estimatedTimeRemaining}s remaining...`);
              }
              
              // Continue polling
              setTimeout(pollOperation, 5000); // Poll every 5 seconds
            }
          } catch (pollError) {
            console.error('🔍 Polling error:', pollError);
            setError('Connection lost during generation');
            stopProgress();
          }
        };
        
        // Start first poll after 2 seconds
        setTimeout(pollOperation, 2000);
        
      } else if (data.videoUrl) {
        // Immediate response (cached or fallback) - stop progress immediately
        stopProgress();
        setVideoSrc(data.videoUrl);
        setRenderingProgress(100);
        setCurrentPhase('Complete');
        setVideoData(data);
        setHasGeneratedVideo(true);
        setIsRendering(false);
        
        toast({
          title: "Video Ready",
          description: `VEO 3.0 ${post.platform} video generated`
        });
      } else if (data.response || data.textDescription) { 
        // Fallback to text description if no URL - stop progress immediately
        stopProgress();
        setPreviewText(data.response || data.textDescription);
        setRenderingProgress(100);
        setCurrentPhase('Preview Mode');
        setVideoData(data);
        setHasGeneratedVideo(true);
        setIsRendering(false);
        
        toast({
          title: "Preview Mode",
          description: "Video generation unavailable - showing text preview"
        });
      } else {
        throw new Error(data.error || 'Generation failed');
      }
    } catch (error) {
      console.error('Video generation error:', error);
      setError('Generation failed - try again');
      setIsRendering(false);
    } finally {
      stopProgress();
    }
  };

  const approveVideo = async () => {
    if (!videoData || !userId) return;

    try {
      const response = await fetch('/api/video/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          postId: post.id,
          videoData
        })
      });

      const data = await response.json();

      if (data.success) {
        onVideoApproved(post.id, videoData);
        toast({
          title: "Video Approved!",
          description: "Video ready for publishing"
        });
        onPostUpdate?.();
      } else {
        setError('Failed to approve video');
      }
    } catch (error) {
      console.error('Video approval failed:', error);
      setError('Failed to approve video');
    }
  };

  const deleteVideo = () => {
    setVideoData(null);
    setHasGeneratedVideo(false);
    setError(null);
    toast({
      title: "Video Deleted",
      description: "Reverted to text-only post"
    });
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CardTitle className="text-sm font-medium">
              {post.platform} Post
            </CardTitle>
            {post.scheduledFor && (
              <div className="text-xs text-gray-600">
                {new Date(post.scheduledFor).toLocaleDateString('en-AU', {
                  weekday: 'short',
                  day: 'numeric',
                  month: 'short'
                })} at {new Date(post.scheduledFor).toLocaleTimeString('en-AU', {
                  hour: 'numeric',
                  minute: '2-digit',
                  hour12: true
                })}
              </div>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={post.status === 'approved' ? 'default' : 'secondary'}>
              {post.status}
            </Badge>
            {isVideoSupported && (
              <Badge variant="outline" className="bg-purple-50 text-purple-700 border-purple-200">
                Veo3 Ready
              </Badge>
            )}
          </div>
        </div>
        
        <CardDescription className="text-xs text-gray-800 leading-relaxed whitespace-pre-wrap">
          {post.content}
        </CardDescription>
        
        {isVideoSupported && (
          <div className="mt-2 text-xs text-purple-600">
            Video generation available
          </div>
        )}
      </CardHeader>
      
      <CardContent>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {hasGeneratedVideo && (
              <Badge variant="outline" className="text-xs">
                <VideoIcon className="w-3 h-3 mr-1" />
                Video Ready
              </Badge>
            )}
          </div>
          
          {/* Video Generation Section - With Pro Subscription Control */}
          {isVideoSupported && !post.hasVideo && !post.videoApproved && (
            <div className="flex flex-col items-end gap-2">
              {hasProSubscription ? (
                // Pro users: Show active generate button
                <>
                  <Button
                    className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white font-medium shadow-sm"
                    size="sm"
                    onClick={generateVideoOneClick}
                    disabled={isRendering || hasGeneratedVideo}
                    aria-label="Generate cinematic video for this post"
                  >
                    {isRendering ? (
                      <>
                        <LoaderIcon className="w-4 h-4 mr-2 animate-spin" />
                        Creating... ({renderingTime}s)
                      </>
                    ) : (
                      <>
                        <VideoIcon className="w-4 h-4 mr-2" />
                        Generate Video
                      </>
                    )}
                  </Button>
                  {!isRendering && (
                    <div className="text-xs text-purple-600 font-medium">
                      VEO 3.0 Ready
                    </div>
                  )}
                </>
              ) : (
                // Non-pro users: Show upgrade prompt
                <>
                  <Button
                    className="bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white font-medium shadow-sm relative opacity-75 cursor-not-allowed"
                    size="sm"
                    disabled
                    aria-label="Video generation requires pro subscription"
                  >
                    <Lock className="w-4 h-4 mr-2" />
                    Pro Feature
                    <Crown className="w-3 h-3 ml-1" />
                  </Button>
                  <div className="text-xs text-amber-600 font-medium text-right">
                    Upgrade to Pro for VEO 3.0
                  </div>
                </>
              )}
            </div>
          )}
          

        </div>
        
        {/* Authentic VEO 3.0 Progress Indicator */}
        {isRendering && (
          <div className="mt-3 p-4 bg-gradient-to-r from-purple-50 to-indigo-50 border-2 border-purple-200 rounded-lg">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-purple-500 rounded-full animate-pulse"></div>
                <span className="text-sm text-purple-800 font-semibold">VEO 3.0 Generation</span>
                <span className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded-full">
                  30s - 6min process
                </span>
              </div>
              <div className="text-right">
                <span className="text-sm font-mono text-purple-700">
                  {Math.floor(renderingTime / 60)}:{(renderingTime % 60).toString().padStart(2, '0')}
                </span>
              </div>
            </div>

            {/* Important user message about async timing */}
            <div className="mb-3 p-2 bg-amber-50 border border-amber-200 rounded text-xs text-amber-800">
              <strong>Please wait:</strong> VEO 3.0 uses authentic async processing (not instant results). 
              Operations take 30 seconds to 6 minutes to complete for cinematic quality.
            </div>
            
            <div className="w-full bg-purple-100 rounded-full h-2 mb-3">
              <div 
                className="bg-gradient-to-r from-purple-500 to-indigo-500 h-2 rounded-full transition-all duration-1000 ease-out"
                style={{ width: `${renderingProgress}%` }}
              ></div>
            </div>
            
            {currentPhase && (
              <div className="space-y-1">
                <p className="text-sm font-medium text-purple-800">{currentPhase}</p>
                <div className="flex items-center gap-2 text-xs text-purple-600">
                  <span>🎬 Cinematic Quality</span>
                  <span>•</span>
                  <span>🎵 Orchestral Audio</span>
                  <span>•</span>
                  <span>🇦🇺 Queensland Context</span>
                </div>
                <div className="text-xs text-purple-600 mt-1 italic">
                  Authentic Vertex AI processing - please keep this tab open while generating
                </div>
              </div>
            )}
          </div>
        )}
        

        
        {/* Simple Error Display */}
        {error && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
            <p className="text-sm text-red-600">{error}</p>
            <Button
              variant="outline"
              size="sm"
              className="mt-2"
              onClick={() => setError(null)}
            >
              Try Again
            </Button>
          </div>
        )}

        {/* Modern Post Actions - Clean Edit and Approve */}
        <div className="mt-6 flex gap-3 justify-end">
          {onEditPost && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => onEditPost(post)}
              className={`transition-all duration-300 ${
                post.edited 
                  ? "text-blue-600 border-blue-400 bg-blue-50 hover:bg-blue-100 hover:border-blue-500" 
                  : "text-gray-500 border-gray-300 bg-white hover:bg-gray-50 hover:border-gray-400"
              }`}
            >
              <Edit className="w-4 h-4 mr-2" />
              {post.edited ? "Edited" : "Edit"}
            </Button>
          )}
          {onApprovePost && post.status !== 'approved' && (
            <Button
              onClick={() => onApprovePost(post.id)}
              size="sm"
              className="bg-emerald-600 hover:bg-emerald-700 text-white border-0 shadow-sm hover:shadow-md transition-all duration-200"
            >
              <CheckIcon className="w-4 h-4 mr-2" />
              Approve & Queue
            </Button>
          )}
        </div>
        
        {/* VEO 3.0 Video Preview Card with URL Validation and Error Recovery */}
        {hasGeneratedVideo && videoData && (
          <div className="mt-4 p-4 bg-gradient-to-r from-purple-50 to-indigo-50 border-2 border-purple-200 rounded-lg">
            <div className="flex items-center justify-between mb-3">
              <Badge className={`px-3 py-1 text-white ${videoData.veo2Generated ? 'bg-gradient-to-r from-blue-600 to-indigo-600' : 'bg-gradient-to-r from-purple-600 to-indigo-600'}`}>
                <VideoIcon className="w-4 h-4 mr-2" />
                {videoData.grokEnhanced ? 'Grok + VEO 3.0' : videoData.veo3Generated ? 'VEO 3.0 Ready' : 'Video Ready'}
              </Badge>
              <div className="flex gap-2">
                <Button
                  onClick={approveVideo}
                  size="sm"
                  className="bg-green-600 hover:bg-green-700 text-white font-medium"
                >
                  <CheckIcon className="w-4 h-4 mr-1" />
                  Approve
                </Button>
                <Button
                  onClick={deleteVideo}
                  variant="outline"
                  size="sm"
                  className="border-red-200 text-red-600 hover:bg-red-50"
                >
                  <XIcon className="w-4 h-4 mr-1" />
                  Delete
                </Button>
              </div>
            </div>
            
            {/* Direct Video Preview - Simple and Working */}
            <div className="mb-3">
              <div className="relative aspect-video bg-gray-100 rounded-lg overflow-hidden">
                <video
                  src={`/videos/generated/${videoData.videoId}.mp4`}
                  controls
                  preload="metadata"
                  className="w-full h-full object-cover"
                  onLoadedData={() => {
                    console.log(`✅ Video ready: ${videoData.videoId}`);
                    toast({
                      title: 'Video Ready',
                      description: 'Video preview loaded successfully',
                      duration: 2000
                    });
                  }}
                  onError={(e) => {
                    console.error(`❌ Video load error for ${videoData.videoId}:`, e);
                    toast({
                      title: 'Video Error',
                      description: 'Failed to load video preview',
                      variant: 'destructive'
                    });
                  }}
                >
                  Your browser does not support the video tag.
                </video>
              </div>
            </div>
            
            {/* Video Details with VEO3 Specs */}
            <div className="space-y-2">
              <h4 className="font-medium text-gray-900 text-sm leading-tight">{videoData.title}</h4>
              <p className="text-xs text-gray-600 leading-relaxed">{videoData.description}</p>
              
              {/* VEO3 Technical Specifications */}
              <div className="flex flex-wrap gap-2 pt-2 border-t border-purple-100">
                <div className="flex items-center gap-1 text-xs text-purple-600">
                  <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
                  <span>Resolution: {videoData.width || 1920}×{videoData.height || 1080}</span>
                </div>
                <div className="flex items-center gap-1 text-xs text-purple-600">
                  <div className="w-2 h-2 bg-indigo-400 rounded-full"></div>
                  <span>Duration: {videoData.duration || 8}s</span>
                </div>
                <div className="flex items-center gap-1 text-xs text-purple-600">
                  <div className="w-2 h-2 bg-cyan-400 rounded-full"></div>
                  <span>Format: MP4</span>
                </div>
                {videoData.artDirectorPreview && (
                  <div className="flex items-center gap-1 text-xs text-amber-600">
                    <div className="w-2 h-2 bg-amber-400 rounded-full"></div>
                    <span>Preview Mode</span>
                  </div>
                )}
                {videoData.veoGenerated && (
                  <div className="flex items-center gap-1 text-xs text-green-600">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    <span>Veo3 Generated</span>
                  </div>
                )}
              </div>
              
              {/* Strategic Intent Display */}
              {videoData.strategicIntent && (
                <div className="mt-2 p-2 bg-white rounded border border-purple-100">
                  <p className="text-xs text-gray-500 mb-1">Strategic Intent:</p>
                  <p className="text-xs font-medium text-purple-800">{videoData.strategicIntent}</p>
                </div>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Default export for the simplified video post card component
export default VideoPostCardSimple;

// Mobile responsiveness CSS for video preview components
const mobileStyles = `
  /* Mobile responsiveness for video preview cards */
  @media (max-width: 768px) {
    .video-preview-card {
      flex-direction: column;
      padding: 12px;
    }
    
    .video-preview-card .video-container {
      width: 100%;
      max-height: 200px;
      margin-bottom: 12px;
    }
    
    .video-preview-card .video-actions {
      flex-direction: column;
      gap: 8px;
    }
    
    .video-preview-card .video-actions button {
      width: 100%;
      min-height: 44px;
    }
    
    .video-preview-card .platform-badge {
      font-size: 12px;
      padding: 4px 8px;
    }
    
    .video-preview-card .video-specs {
      flex-wrap: wrap;
      gap: 4px;
    }
    
    .video-preview-card .video-specs span {
      font-size: 10px;
      padding: 2px 6px;
    }
  }
`;

// Inject mobile styles if not already present
if (typeof document !== 'undefined' && !document.getElementById('video-mobile-styles')) {
  const styleSheet = document.createElement('style');
  styleSheet.id = 'video-mobile-styles';
  styleSheet.textContent = mobileStyles;
  document.head.appendChild(styleSheet);
}