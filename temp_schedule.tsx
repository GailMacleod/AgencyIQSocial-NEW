import { useLocation } from "wouter";
import { Calendar, Clock, CheckCircle, XCircle, RotateCcw, Play, Eye, ThumbsUp, X, Sparkles, Brain, Target, Users, MapPin, Edit3, Save } from "lucide-react";
import CalendarCard from "@/components/calendar-card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { useState, useEffect } from "react";
import { format, addDays, startOfMonth, endOfMonth, isSameDay, isToday } from "date-fns";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";
import BackButton from "@/components/back-button";
import { MetaPixelTracker } from "@/lib/meta-pixel";
import AutoPostingEnforcer from "@/components/auto-posting-enforcer";
import { VideoPostCard } from "@/components/VideoPostCard";

interface Post {
  id: number;
  platform: string;
  content: string;
  status: string;
  scheduledFor: string;
  publishedAt?: string;
  errorLog?: string;
  aiRecommendation?: string;
  aiScore?: number;
  localEvent?: string;
  analytics?: {
    reach: number;
    engagement: number;
    impressions: number;
  };
}

interface User {
  id: number;
  email: string;
  phone: string;
  subscriptionPlan: string;
  remainingPosts: number;
  totalPosts: number;
}

interface SubscriptionUsage {
  subscriptionPlan: string;
  totalAllocation: number;
  remainingPosts: number;
  usedPosts: number;
  publishedPosts: number;
  failedPosts: number;
  partialPosts: number;
  planLimits: {
    posts: number;
    reach: number;
    engagement: number;
  };
  usagePercentage: number;
}

interface BrandPurpose {
  id: number;
  brandName: string;
  productsServices: string;
  corePurpose: string;
  audience: string;
  jobToBeDone: string;
  motivations: string;
  painPoints: string;
  goals: any;
  contactDetails: any;
}

interface AIScheduleData {
  posts: Post[];
  analysis: {
    jtbdScore: number;
    platformWeighting: { [platform: string]: number };
    tone: string;
    postTypeAllocation: { [type: string]: number };
    suggestions: string[];
  };
  schedule: {
    optimalTimes: { [platform: string]: string[] };
    eventAlignment: string[];
    contentThemes: string[];
  };
}

export default function IntelligentSchedule() {
// Component continues...
