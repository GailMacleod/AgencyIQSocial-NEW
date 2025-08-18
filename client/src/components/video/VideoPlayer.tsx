import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { PlayIcon, PauseIcon, RotateCcwIcon } from 'lucide-react';
import { VideoData } from '@/types';

interface VideoPlayerProps {
  videoData: VideoData;
  onTimeUpdate?: (currentTime: number) => void;
  maxDuration?: number;
  className?: string;
}

export function VideoPlayer({ 
  videoData, 
  onTimeUpdate, 
  maxDuration = 15,
  className = ''
}: VideoPlayerProps): JSX.Element {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const videoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const handleLoadedMetadata = (): void => {
      setDuration(Math.min(video.duration, maxDuration));
      setIsLoading(false);
    };

    const handleTimeUpdate = (): void => {
      const time = video.currentTime;
      setCurrentTime(time);
      onTimeUpdate?.(time);
      
      // Enforce max duration
      if (time >= maxDuration) {
        video.pause();
        setIsPlaying(false);
      }
    };

    const handlePlay = (): void => setIsPlaying(true);
    const handlePause = (): void => setIsPlaying(false);

    video.addEventListener('loadedmetadata', handleLoadedMetadata);
    video.addEventListener('timeupdate', handleTimeUpdate);
    video.addEventListener('play', handlePlay);
    video.addEventListener('pause', handlePause);

    return () => {
      video.removeEventListener('loadedmetadata', handleLoadedMetadata);
      video.removeEventListener('timeupdate', handleTimeUpdate);
      video.removeEventListener('play', handlePlay);
      video.removeEventListener('pause', handlePause);
    };
  }, [maxDuration, onTimeUpdate]);

  const togglePlayPause = (): void => {
    const video = videoRef.current;
    if (!video) return;

    if (isPlaying) {
      video.pause();
    } else {
      video.play();
    }
  };

  const restart = (): void => {
    const video = videoRef.current;
    if (!video) return;

    video.currentTime = 0;
    setCurrentTime(0);
    if (isPlaying) {
      video.play();
    }
  };

  const progressPercent = duration > 0 ? (currentTime / duration) * 100 : 0;

  return (
    <div className={`relative ${className}`}>
      <video
        ref={videoRef}
        src={videoData.url}
        className="w-full h-auto rounded-lg"
        muted
        loop={false}
        preload="metadata"
        onError={() => setIsLoading(false)}
      />
      
      {isLoading && (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-100 rounded-lg">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
        </div>
      )}

      <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/60 to-transparent p-4 rounded-b-lg">
        <div className="flex items-center gap-3">
          <Button
            size="sm"
            variant="secondary"
            onClick={togglePlayPause}
            disabled={isLoading}
            className="bg-white/20 hover:bg-white/30"
          >
            {isPlaying ? (
              <PauseIcon className="w-4 h-4" />
            ) : (
              <PlayIcon className="w-4 h-4" />
            )}
          </Button>
          
          <Button
            size="sm"
            variant="secondary"
            onClick={restart}
            disabled={isLoading}
            className="bg-white/20 hover:bg-white/30"
          >
            <RotateCcwIcon className="w-4 h-4" />
          </Button>
          
          <div className="flex-1">
            <Progress value={progressPercent} className="h-2" />
            <div className="flex justify-between text-xs text-white mt-1">
              <span>{Math.round(currentTime)}s</span>
              <span>{Math.round(duration)}s</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}