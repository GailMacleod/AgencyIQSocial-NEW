/**
 * Lazy Video Preview Component
 * Only loads video when needed, uses GCS URIs, no local storage
 */

import { useState, useRef, useEffect } from 'react';
import { Play, Loader2, AlertCircle } from 'lucide-react';

interface LazyVideoPreviewProps {
  videoId: string;
  gcsUri?: string;
  metadata?: {
    duration?: number;
    aspectRatio?: string;
    quality?: string;
    format?: string;
  };
  onLoad?: () => void;
  onError?: (error: string) => void;
}

export function LazyVideoPreview({ 
  videoId, 
  gcsUri, 
  metadata, 
  onLoad, 
  onError 
}: LazyVideoPreviewProps) {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [videoUrl, setVideoUrl] = useState<string | null>(null);
  const videoRef = useRef<HTMLVideoElement>(null);

  // Auto-load video when component mounts with gcsUri
  useEffect(() => {
    const loadVideo = async () => {
      console.log(`🔍 LazyVideoPreview mounted - videoId: ${videoId}, gcsUri: ${gcsUri}, isLoaded: ${isLoaded}, isLoading: ${isLoading}`);
      
      if (!gcsUri || isLoaded || isLoading) {
        console.log(`⏭️ Skipping auto-load - no gcsUri (${!gcsUri}) or already loaded (${isLoaded}) or loading (${isLoading})`);
        return;
      }

      setIsLoading(true);
      setError(null);

      try {
        console.log(`🔄 Auto-loading video: ${videoId} with gcsUri: ${gcsUri}`);
        
        // Request optimized serving URL from backend
        const response = await fetch(`/api/video/serve/${videoId}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gcsUri })
        });

        if (!response.ok) {
          throw new Error(`Failed to load video: ${response.status}`);
        }

        const data = await response.json();
        console.log(`📡 Video serve response:`, data);
        setVideoUrl(data.servingUrl);
        setIsLoaded(true);
        onLoad?.();
        
        console.log(`✅ Video auto-loaded: ${videoId} with URL: ${data.servingUrl}`);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : 'Failed to load video';
        setError(errorMsg);
        onError?.(errorMsg);
        console.error(`❌ Video auto-loading failed: ${errorMsg}`);
      } finally {
        setIsLoading(false);
      }
    };

    loadVideo();
  }, [gcsUri, videoId]);

  // Lazy load video when user clicks play OR auto-load on mount
  const handleLoadVideo = async () => {
    if (isLoaded || isLoading) return;

    setIsLoading(true);
    setError(null);

    try {
      console.log(`🔄 Loading video on-demand: ${videoId}`);
      
      // Request optimized serving URL from backend
      const response = await fetch(`/api/video/serve/${videoId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ gcsUri })
      });

      if (!response.ok) {
        throw new Error(`Failed to load video: ${response.status}`);
      }

      const data = await response.json();
      setVideoUrl(data.servingUrl);
      setIsLoaded(true);
      onLoad?.();
      
      console.log(`✅ Video loaded on-demand: ${videoId}`);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to load video';
      setError(errorMsg);
      onError?.(errorMsg);
      console.error(`❌ Video loading failed: ${errorMsg}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Auto-cleanup when component unmounts
  useEffect(() => {
    return () => {
      if (videoUrl && videoUrl.includes('/temp-video/')) {
        // Signal backend to cleanup temp file
        fetch(`/api/video/cleanup/${videoId}`, { method: 'POST' })
          .catch(() => {}); // Silent cleanup
      }
    };
  }, [videoId, videoUrl]);

  const aspectRatioClass = metadata?.aspectRatio === '9:16' 
    ? 'aspect-[9/16]' 
    : 'aspect-video';

  return (
    <div className={`relative ${aspectRatioClass} bg-gray-100 rounded-lg overflow-hidden`}>
      {!isLoaded && !isLoading && (
        <div 
          className="absolute inset-0 flex flex-col items-center justify-center cursor-pointer bg-gradient-to-br from-gray-100 to-gray-200 hover:from-gray-200 hover:to-gray-300 transition-all"
          onClick={handleLoadVideo}
        >
          <Play className="h-16 w-16 text-gray-600 mb-4" />
          <div className="text-center px-4">
            <p className="text-sm font-medium text-gray-800 mb-2">
              Click to load video preview
            </p>
            {metadata && (
              <div className="text-xs text-gray-600 space-y-1">
                <p>Duration: {metadata.duration}s</p>
                <p>Quality: {metadata.quality}</p>
                <p>Format: {metadata.format}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {isLoading && (
        <div className="absolute inset-0 flex flex-col items-center justify-center bg-gray-100">
          <Loader2 className="h-8 w-8 animate-spin text-blue-600 mb-2" />
          <p className="text-sm text-gray-600">Loading video...</p>
        </div>
      )}

      {error && (
        <div className="absolute inset-0 flex flex-col items-center justify-center bg-red-50">
          <AlertCircle className="h-8 w-8 text-red-600 mb-2" />
          <p className="text-sm text-red-600 text-center px-4">{error}</p>
          <button 
            onClick={handleLoadVideo}
            className="mt-2 text-xs text-red-700 hover:text-red-800 underline"
          >
            Try again
          </button>
        </div>
      )}

      {isLoaded && videoUrl && (
        <video
          ref={videoRef}
          src={videoUrl}
          controls
          preload="metadata"
          className="w-full h-full object-cover"
          onLoadedData={() => console.log(`✅ Video ready: ${videoId}`)}
          onError={() => setError('Video playback failed')}
        >
          Your browser does not support the video tag.
        </video>
      )}

      {/* Memory-optimized metadata overlay */}
      <div className="absolute bottom-2 left-2 bg-black/50 text-white text-xs px-2 py-1 rounded">
        {gcsUri ? 'GCS Ready' : 'No Source'}
      </div>
    </div>
  );
}

export default LazyVideoPreview;