import { useEffect, useState, useRef, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';

interface BrandPost {
  id: number;
  platform: string;
  content: string;
  scheduledFor: string;
  status: string;
  aiRecommendation: string;
}

const Schedule = () => {
  const [brandPosts, setBrandPosts] = useState<BrandPost[]>([]);
  const [syncStatus, setSyncStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const cacheRef = useRef(new Map<string, BrandPost[]>());
  const lastSyncRef = useRef<string | null>(null);

  // Fetch brand posts from xAI API with enhanced logging
  const { data: brandPostsData, isLoading, error } = useQuery({
    queryKey: ['/api/brand-posts'],
    queryFn: async () => {
      const currentDate = new Date().toISOString().split('T')[0];
      console.log(`Initiating brand posts fetch for ${currentDate}`);
      
      const response = await fetch('/api/brand-posts', {
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        console.error(`Brand posts API failed: ${response.status} ${response.statusText}`);
        throw new Error(`API request failed: ${response.status}`);
      }
      
      const data = await response.json();
      console.log(`Brand posts API response received:`, data);
      return data;
    },
    retry: 2,
    retryDelay: 1000,
    staleTime: 5 * 60 * 1000, // 5 minutes cache
    gcTime: 10 * 60 * 1000 // 10 minutes garbage collection
  });

  // Optimized sync with caching and detailed logging
  const syncBrandPosts = useCallback((postsData: BrandPost[], userEmail: string, expectedCount?: number) => {
    const currentDate = new Date().toISOString().split('T')[0];
    
    // Reset postsRef on each fetch to prevent doubling
    cacheRef.current.clear();
    lastSyncRef.current = null;
    
    try {
      console.log(`Schedule refreshed for ${userEmail}: ${postsData.length} posts`);
      
      // Verify postsRef matches the logged count
      if (expectedCount && postsData.length !== expectedCount) {
        console.warn(`Post count mismatch for ${userEmail}: expected ${expectedCount}, got ${postsData.length}`);
      } else if (expectedCount) {
        console.log(`Schedule verified for ${userEmail}: ${postsData.length} posts`);
      }
      
      setBrandPosts(postsData);
      setSyncStatus('success');
      
      console.log(`Schedule synced with Brand Purpose for ${currentDate} - ${postsData.length} posts loaded`);
    } catch (error: any) {
      setSyncStatus('error');
      console.error(`Schedule sync failed for ${currentDate}:`, error);
      console.error('Error details:', {
        message: error?.message || 'Unknown error',
        stack: error?.stack,
        postsData
      });
      
      setBrandPosts([]);
    }
  }, []);

  // Sync brand posts with schedule
  useEffect(() => {
    if (brandPostsData?.posts) {
      const expectedCount = brandPostsData.postCount || 30; // Default to professional plan
      syncBrandPosts(brandPostsData.posts, 'gailm@macleodglba.com.au', expectedCount);
    } else if (error) {
      const currentDate = new Date().toISOString().split('T')[0];
      console.error(`Brand posts fetch failed for ${currentDate}:`, error);
      setSyncStatus('error');
      setBrandPosts([]);
    }
  }, [brandPostsData, error, syncBrandPosts]);

  // Handle dropdown display of all planned posts
  const getPostsForDay = (date: Date): BrandPost[] => {
    const targetDate = new Date(date).toISOString().split('T')[0];
    return brandPosts.filter(post => {
      const postDate = new Date(post.scheduledFor).toISOString().split('T')[0];
      return postDate === targetDate;
    });
  };

  return {
    brandPosts,
    syncStatus,
    isLoading,
    error,
    getPostsForDay
  };
};

export default Schedule;