// Core interfaces for TheAgencyIQ

export interface Post {
  id: number;
  platform: string;
  content: string;
  status: string;
  scheduledFor: string;
  publishedAt?: string;
  errorLog?: string;
  aiRecommendation?: string;
  localEvent?: string;
  hasVideo?: boolean;
  videoApproved?: boolean;
  videoData?: VideoData;
  approvedAt?: string;
  analytics?: PostAnalytics;
}

export interface PostAnalytics {
  reach: number;
  engagement: number;
  impressions: number;
  likes?: number;
  comments?: number;
  shares?: number;
  clicks?: number;
}

export interface User {
  id: number;
  email: string;
  phone: string;
  subscriptionPlan: string;
  remainingPosts: number;
  totalPosts: number;
}

export interface BrandPurpose {
  id: number;
  brandName: string;
  productsServices: string;
  corePurpose: string;
  audience: string;
  jobToBeDone: string;
  motivations: string;
  painPoints: string;
  goals: BrandGoals;
  contactDetails: ContactDetails;
}

export interface BrandGoals {
  driveTraffic: boolean;
  websiteUrl?: string;
  trafficTarget?: string;
  buildBrand: boolean;
  followerTarget?: string;
  reachTarget?: string;
  makeSales: boolean;
  salesUrl?: string;
  salesTarget?: string;
  conversionTarget?: string;
  generateLeads: boolean;
  leadTarget?: string;
  engagementTarget?: string;
  informEducate: boolean;
  keyMessage?: string;
  educationTarget?: string;
}

export interface ContactDetails {
  email?: string;
  phone?: string;
}

export interface VideoData {
  videoId: string;
  url: string;
  quality: string;
  format: string;
  size: string;
}

export interface VideoPrompt {
  type: 'short-form' | 'ASMR';
  content: string;
  duration: string;
  style: string;
}

export interface CalendarDay {
  date: Date;
  posts: Post[];
  aiInsight?: string;
  localEvents?: string[];
  isOptimalDay: boolean;
}

export interface PlatformConnection {
  platform: string;
  isConnected: boolean;
  username?: string;
  profilePicture?: string;
  lastSync?: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export type Platform = 'facebook' | 'instagram' | 'linkedin' | 'youtube' | 'x';
export type PostStatus = 'draft' | 'approved' | 'published' | 'failed';
export type SubscriptionPlan = 'starter' | 'growth' | 'professional';