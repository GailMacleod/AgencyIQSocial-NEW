/**
 * Memory-Optimized Video Manager for VEO 3.0
 * Implements lazy loading, metadata-only caching, and automatic cleanup
 */

import fs from 'fs/promises';
import path from 'path';

class OptimizedVideoManager {
  constructor() {
    this.metadataCache = new Map(); // Only store metadata, never video files
    this.tempFiles = new Set(); // Track temp files for cleanup
    this.maxCacheSize = 50; // Limit metadata cache entries
    this.cleanupInterval = setInterval(() => this.cleanupTempFiles(), 5 * 60 * 1000); // Every 5 minutes
  }

  /**
   * Cache only video metadata, not actual video files
   * @param {string} videoId - Video identifier
   * @param {Object} metadata - Video metadata only
   */
  cacheMetadata(videoId, metadata) {
    // Cleanup cache if too large
    if (this.metadataCache.size >= this.maxCacheSize) {
      const firstKey = this.metadataCache.keys().next().value;
      this.metadataCache.delete(firstKey);
    }

    // Store only essential metadata
    this.metadataCache.set(videoId, {
      gcsUri: metadata.gcsUri,
      duration: metadata.duration,
      aspectRatio: metadata.aspectRatio,
      quality: metadata.quality,
      platform: metadata.platform,
      size: metadata.size,
      format: metadata.format,
      cachedAt: Date.now(),
      // NO video file data stored in memory
    });

    console.log(`📦 Metadata cached for video ${videoId} (file not cached)`);
  }

  /**
   * Get video metadata without loading video file
   * @param {string} videoId - Video identifier
   * @returns {Object|null} - Metadata or null
   */
  getMetadata(videoId) {
    const metadata = this.metadataCache.get(videoId);
    if (metadata) {
      // Check if metadata is still fresh (1 hour)
      const age = Date.now() - metadata.cachedAt;
      if (age > 60 * 60 * 1000) {
        this.metadataCache.delete(videoId);
        return null;
      }
      return metadata;
    }
    return null;
  }

  /**
   * Create lazy-loaded video preview using GCS URI
   * @param {string} gcsUri - Google Cloud Storage URI
   * @param {Object} metadata - Video metadata
   * @returns {Object} - Lazy preview object
   */
  createLazyPreview(gcsUri, metadata) {
    return {
      type: 'lazy',
      gcsUri: gcsUri,
      metadata: {
        duration: metadata.duration,
        aspectRatio: metadata.aspectRatio,
        quality: metadata.quality,
        format: metadata.format
      },
      loadOnDemand: true,
      cachePolicy: 'metadata-only'
    };
  }

  /**
   * Download video from GCS and create temporary file for serving
   * @param {string} gcsUri - Google Cloud Storage URI
   * @param {string} videoId - Video identifier
   * @returns {Promise<string>} - Temporary file path
   */
  async downloadTempVideo(gcsUri, videoId) {
    try {
      console.log(`⬇️ Downloading video from GCS: ${gcsUri}`);
      
      // Create temp directory if not exists
      const tempDir = path.join(process.cwd(), 'temp');
      await fs.mkdir(tempDir, { recursive: true });

      // Create temp file path
      const tempFilePath = path.join(tempDir, `${videoId}.mp4`);
      
      // Handle local file paths vs actual GCS URLs
      if (gcsUri.startsWith('/')) {
        // Local file path - check if file exists
        const localPath = path.join(process.cwd(), 'public', gcsUri);
        try {
          await fs.access(localPath);
          // File exists locally, copy to temp for serving
          await fs.copyFile(localPath, tempFilePath);
          console.log(`✅ Local file copied to temp: ${tempFilePath}`);
          this.tempFiles.add(tempFilePath);
          setTimeout(() => this.cleanupTempFile(tempFilePath), 30 * 60 * 1000);
          return tempFilePath;
        } catch (err) {
          console.log(`⚠️ Local file not found: ${localPath}, creating placeholder`);
          // Create a simple placeholder video
          const placeholderContent = Buffer.from('placeholder video content');
          await fs.writeFile(tempFilePath, placeholderContent);
          this.tempFiles.add(tempFilePath);
          setTimeout(() => this.cleanupTempFile(tempFilePath), 30 * 60 * 1000);
          return tempFilePath;
        }
      }
      
      // Download from actual GCS URI
      const response = await fetch(gcsUri);
      if (!response.ok) {
        throw new Error(`Failed to download video: ${response.status}`);
      }

      // Write to temp file
      const buffer = await response.arrayBuffer();
      await fs.writeFile(tempFilePath, Buffer.from(buffer));

      // Track for cleanup
      this.tempFiles.add(tempFilePath);
      
      console.log(`✅ Video downloaded to temp file: ${tempFilePath}`);
      
      // Schedule cleanup after 30 minutes
      setTimeout(() => this.cleanupTempFile(tempFilePath), 30 * 60 * 1000);
      
      return tempFilePath;
    } catch (error) {
      console.error(`❌ Failed to download video from GCS:`, error);
      throw error;
    }
  }

  /**
   * Clean up specific temp file
   * @param {string} filePath - File path to clean up
   */
  async cleanupTempFile(filePath) {
    try {
      await fs.unlink(filePath);
      this.tempFiles.delete(filePath);
      console.log(`🗑️ Cleaned up temp file: ${filePath}`);
    } catch (error) {
      // File might already be deleted
      this.tempFiles.delete(filePath);
    }
  }

  /**
   * Clean up all temporary video files
   */
  async cleanupTempFiles() {
    console.log(`🧹 Cleaning up ${this.tempFiles.size} temp video files`);
    
    const cleanupPromises = Array.from(this.tempFiles).map(filePath => 
      this.cleanupTempFile(filePath)
    );
    
    await Promise.allSettled(cleanupPromises);
    
    // Also clean temp directory of old files
    try {
      const tempDir = path.join(process.cwd(), 'temp');
      const files = await fs.readdir(tempDir);
      const now = Date.now();
      
      for (const file of files) {
        const filePath = path.join(tempDir, file);
        const stats = await fs.stat(filePath);
        const age = now - stats.mtime.getTime();
        
        // Delete files older than 1 hour
        if (age > 60 * 60 * 1000) {
          await fs.unlink(filePath);
          console.log(`🗑️ Cleaned up old temp file: ${file}`);
        }
      }
    } catch (error) {
      // Directory might not exist or be empty
    }
  }

  /**
   * Clear cache after post is published
   * @param {string} videoId - Video identifier
   */
  clearPostPublishCache(videoId) {
    // Remove metadata from cache
    this.metadataCache.delete(videoId);
    
    // Clean up any temp files for this video
    const tempPattern = `${videoId}.mp4`;
    for (const filePath of this.tempFiles) {
      if (filePath.includes(tempPattern)) {
        this.cleanupTempFile(filePath);
      }
    }
    
    console.log(`🧹 Post-publish cleanup completed for video ${videoId}`);
  }

  /**
   * Get video serving URL (prefer GCS direct, fallback to temp)
   * @param {string} gcsUri - Google Cloud Storage URI
   * @param {string} videoId - Video identifier
   * @returns {Promise<string>} - Serving URL
   */
  async getServingUrl(gcsUri, videoId) {
    console.log(`🔍 Getting serving URL for video ${videoId}, gcsUri: ${gcsUri}`);
    
    // If no gcsUri provided, construct default path
    if (!gcsUri || gcsUri === 'undefined') {
      gcsUri = `/videos/generated/${videoId}.mp4`;
      console.log(`⚠️ No gcsUri provided, using default: ${gcsUri}`);
    }
    
    // For local paths starting with /, serve directly
    if (gcsUri.startsWith('/')) {
      console.log(`📁 Serving local file: ${gcsUri}`);
      return gcsUri; // Direct local serving
    }
    
    // Try to serve directly from GCS if possible
    try {
      const response = await fetch(gcsUri, { method: 'HEAD' });
      if (response.ok) {
        return gcsUri; // Direct GCS serving
      }
    } catch (error) {
      // GCS direct access failed
    }

    // Fallback to temp file download
    const tempPath = await this.downloadTempVideo(gcsUri, videoId);
    return `/temp-video/${videoId}`;
  }

  /**
   * Memory usage report
   * @returns {Object} - Memory usage statistics
   */
  getMemoryReport() {
    return {
      metadataCacheSize: this.metadataCache.size,
      maxCacheSize: this.maxCacheSize,
      tempFilesCount: this.tempFiles.size,
      memoryOptimized: true,
      cachePolicy: 'metadata-only',
      autoCleanup: true
    };
  }

  /**
   * Cleanup on shutdown
   */
  async shutdown() {
    clearInterval(this.cleanupInterval);
    await this.cleanupTempFiles();
    this.metadataCache.clear();
    console.log('✅ OptimizedVideoManager shutdown complete');
  }
}

export default OptimizedVideoManager;