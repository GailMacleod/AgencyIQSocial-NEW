/**
 * ADMIN QUOTA DASHBOARD
 * Real-time monitoring and management of persistent quota system
 */

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { 
  Users, 
  Activity, 
  AlertTriangle, 
  RefreshCw, 
  Trash2,
  Shield,
  TrendingUp,
  Server,
  Database
} from 'lucide-react';

interface QuotaStats {
  totalUsers: number;
  activeToday: number;
  quotaStats: {
    free: { users: number; totalAPICalls: number; totalVideoGens: number };
    professional: { users: number; totalAPICalls: number; totalVideoGens: number };
    enterprise: { users: number; totalAPICalls: number; totalVideoGens: number };
  };
}

interface UserQuota {
  userId: number;
  dailyAPICalls: number;
  dailyVideoGens: number;
  dailyContentGens: number;
  lastResetDate: string;
  subscriptionTier: 'free' | 'professional' | 'enterprise';
  quotaLimits: {
    dailyAPILimit: number;
    dailyVideoLimit: number;
    dailyContentLimit: number;
  };
}

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042'];

export default function AdminQuotaDashboard() {
  const [stats, setStats] = useState<QuotaStats | null>(null);
  const [userQuota, setUserQuota] = useState<UserQuota | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedUserId, setSelectedUserId] = useState('2');
  const { toast } = useToast();

  const fetchQuotaStats = async () => {
    try {
      const response = await fetch('/api/admin/quota-stats', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' }
      });
      
      if (response.ok) {
        const data = await response.json();
        setStats(data.stats);
      } else {
        throw new Error('Failed to fetch quota stats');
      }
    } catch (error) {
      console.error('Error fetching quota stats:', error);
      toast({
        title: "Error",
        description: "Failed to load quota statistics",
        variant: "destructive"
      });
    }
  };

  const fetchUserQuota = async (userId: string) => {
    try {
      const response = await fetch(`/api/admin/user-quota/${userId}`, {
        credentials: 'include',
        headers: { 'Accept': 'application/json' }
      });
      
      if (response.ok) {
        const data = await response.json();
        setUserQuota(data.quota);
      } else {
        throw new Error('Failed to fetch user quota');
      }
    } catch (error) {
      console.error('Error fetching user quota:', error);
      toast({
        title: "Error", 
        description: "Failed to load user quota",
        variant: "destructive"
      });
    }
  };

  const resetUserQuota = async (userId: string) => {
    try {
      const response = await fetch(`/api/admin/reset-quota/${userId}`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' }
      });
      
      if (response.ok) {
        toast({
          title: "Success",
          description: `Quota reset for user ${userId}`,
        });
        await fetchUserQuota(userId);
        await fetchQuotaStats();
      } else {
        throw new Error('Failed to reset quota');
      }
    } catch (error) {
      console.error('Error resetting quota:', error);
      toast({
        title: "Error",
        description: "Failed to reset quota",
        variant: "destructive"
      });
    }
  };

  const cleanupOldQuotas = async () => {
    try {
      const response = await fetch('/api/admin/cleanup-quotas', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ daysOld: 30 })
      });
      
      if (response.ok) {
        const data = await response.json();
        toast({
          title: "Success",
          description: `Cleaned up ${data.cleanedCount} old quota records`,
        });
        await fetchQuotaStats();
      } else {
        throw new Error('Failed to cleanup quotas');
      }
    } catch (error) {
      console.error('Error cleaning up quotas:', error);
      toast({
        title: "Error",
        description: "Failed to cleanup quota records",
        variant: "destructive"
      });
    }
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([
        fetchQuotaStats(),
        fetchUserQuota(selectedUserId)
      ]);
      setLoading(false);
    };

    loadData();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, [selectedUserId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const tierData = stats ? [
    { name: 'Free', users: stats.quotaStats.free.users, color: '#0088FE' },
    { name: 'Professional', users: stats.quotaStats.professional.users, color: '#00C49F' },
    { name: 'Enterprise', users: stats.quotaStats.enterprise.users, color: '#FFBB28' }
  ] : [];

  const usageData = stats ? [
    { tier: 'Free', api: stats.quotaStats.free.totalAPICalls, video: stats.quotaStats.free.totalVideoGens },
    { tier: 'Professional', api: stats.quotaStats.professional.totalAPICalls, video: stats.quotaStats.professional.totalVideoGens },
    { tier: 'Enterprise', api: stats.quotaStats.enterprise.totalAPICalls, video: stats.quotaStats.enterprise.totalVideoGens }
  ] : [];

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Quota Management Dashboard</h1>
          <p className="text-gray-600">Monitor persistent quota usage and prevent resource abuse</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={() => fetchQuotaStats()} variant="outline" size="sm">
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button onClick={cleanupOldQuotas} variant="outline" size="sm">
            <Trash2 className="h-4 w-4 mr-2" />
            Cleanup Old Records
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <div className="p-2 bg-blue-100 rounded-lg">
                <Users className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Total Users</p>
                <p className="text-2xl font-bold text-gray-900">{stats?.totalUsers || 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <div className="p-2 bg-green-100 rounded-lg">
                <Activity className="h-6 w-6 text-green-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Active Today</p>
                <p className="text-2xl font-bold text-gray-900">{stats?.activeToday || 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <div className="p-2 bg-purple-100 rounded-lg">
                <Database className="h-6 w-6 text-purple-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Storage</p>
                <p className="text-2xl font-bold text-gray-900">Replit DB</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <div className="p-2 bg-orange-100 rounded-lg">
                <Shield className="h-6 w-6 text-orange-600" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Protection</p>
                <p className="text-2xl font-bold text-gray-900">Active</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* User Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>User Distribution by Tier</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={tierData}
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="users"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {tierData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Usage Analytics */}
        <Card>
          <CardHeader>
            <CardTitle>Daily Usage by Tier</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={usageData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="tier" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="api" fill="#8884d8" name="API Calls" />
                <Bar dataKey="video" fill="#82ca9d" name="Video Generations" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Individual User Quota Management */}
      <Card>
        <CardHeader>
          <CardTitle>Individual User Quota Management</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-4 items-center">
            <label className="text-sm font-medium">User ID:</label>
            <input
              type="number"
              value={selectedUserId}
              onChange={(e) => setSelectedUserId(e.target.value)}
              className="border rounded px-3 py-1 w-24"
              min="1"
            />
            <Button onClick={() => fetchUserQuota(selectedUserId)} size="sm">
              Load Quota
            </Button>
            <Button 
              onClick={() => resetUserQuota(selectedUserId)} 
              variant="destructive" 
              size="sm"
            >
              Reset Quota
            </Button>
          </div>

          {userQuota && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 border rounded-lg">
                <h4 className="font-medium text-gray-900">API Calls</h4>
                <div className="flex items-center gap-2 mt-2">
                  <span className="text-2xl font-bold">{userQuota.dailyAPICalls}</span>
                  <span className="text-gray-500">/ {userQuota.quotaLimits.dailyAPILimit}</span>
                  <Badge variant={userQuota.dailyAPICalls >= userQuota.quotaLimits.dailyAPILimit ? "destructive" : "default"}>
                    {Math.round((userQuota.dailyAPICalls / userQuota.quotaLimits.dailyAPILimit) * 100)}%
                  </Badge>
                </div>
              </div>

              <div className="p-4 border rounded-lg">
                <h4 className="font-medium text-gray-900">Video Generations</h4>
                <div className="flex items-center gap-2 mt-2">
                  <span className="text-2xl font-bold">{userQuota.dailyVideoGens}</span>
                  <span className="text-gray-500">/ {userQuota.quotaLimits.dailyVideoLimit}</span>
                  <Badge variant={userQuota.dailyVideoGens >= userQuota.quotaLimits.dailyVideoLimit ? "destructive" : "default"}>
                    {Math.round((userQuota.dailyVideoGens / userQuota.quotaLimits.dailyVideoLimit) * 100)}%
                  </Badge>
                </div>
              </div>

              <div className="p-4 border rounded-lg">
                <h4 className="font-medium text-gray-900">Content Generations</h4>
                <div className="flex items-center gap-2 mt-2">
                  <span className="text-2xl font-bold">{userQuota.dailyContentGens}</span>
                  <span className="text-gray-500">/ {userQuota.quotaLimits.dailyContentLimit}</span>
                  <Badge variant={userQuota.dailyContentGens >= userQuota.quotaLimits.dailyContentLimit ? "destructive" : "default"}>
                    {Math.round((userQuota.dailyContentGens / userQuota.quotaLimits.dailyContentLimit) * 100)}%
                  </Badge>
                </div>
              </div>
            </div>
          )}

          {userQuota && (
            <div className="p-4 bg-gray-50 rounded-lg">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="font-medium">Subscription Tier:</span>
                  <Badge className="ml-2" variant="outline">{userQuota.subscriptionTier}</Badge>
                </div>
                <div>
                  <span className="font-medium">Last Reset:</span>
                  <span className="ml-2 text-gray-600">{userQuota.lastResetDate}</span>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* System Status */}
      <Alert>
        <Shield className="h-4 w-4" />
        <AlertDescription>
          Quota system is operational with persistent Replit DB storage. 
          All quotas reset daily and provide burst protection against resource abuse.
          Free tier: 5 API calls, 1 video/day. Professional: 100 API calls, 10 videos/day.
        </AlertDescription>
      </Alert>
    </div>
  );
}