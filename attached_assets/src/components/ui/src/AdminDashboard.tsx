import React, { useState, useEffect } from 'react';
import { apiRequest } from '../lib/queryClient';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { useToast } from '../hooks/use-toast';
import { Download, Users, Gift, Calendar, Database, Activity } from 'lucide-react';
import GiftCertificateTracker from './GiftCertificateTracker';

interface GiftCertificate {
  code: string;
  redeemed: boolean;
  plan: string;
  createdFor: string;
  redeemedAt?: string;
}

interface UserData {
  phone: string;
  email: string;
  plan: string;
  start: string;
  ledger: any[];
  posts: any[];
  gifts: GiftCertificate[];
}

interface DataLocation {
  dataSource: string;
  giftSource: string;
}

const AdminDashboard: React.FC = () => {
  const [users, setUsers] = useState<UserData[]>([]);
  const [dataLocation, setDataLocation] = useState<DataLocation | null>(null);
  const [loading, setLoading] = useState(true);
  const [exportLoading, setExportLoading] = useState(false);
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [adminToken, setAdminToken] = useState('');
  const [activeTab, setActiveTab] = useState<'overview' | 'certificates'>('overview');
  const { toast } = useToast();

  // Role-based access control
  const checkAdminAccess = async () => {
    try {
      const response = await fetch('/api/admin/verify', {
        headers: { 
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setIsAuthorized(data.isAdmin);
        return data.isAdmin;
      }
      return false;
    } catch (error) {
      console.error('Admin verification error:', error);
      return false;
    }
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Check admin authorization first
        const hasAccess = await checkAdminAccess();
        if (!hasAccess) {
          toast({
            title: "Access Denied",
            description: "You don't have admin privileges to access this dashboard",
            variant: "destructive"
          });
          setLoading(false);
          return;
        }

        // Fetch data location first
        const locationResponse = await fetch('/api/locate-data');
        const locationData = await locationResponse.json();
        setDataLocation(locationData);

        // Fetch user data with validated admin token
        const response = await fetch('/api/admin/users', {
          headers: { 
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'application/json'
          }
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch admin data');
        }
        
        const userData = await response.json();
        console.log('Admin data with gifts loaded:', userData);
        setUsers(userData);
      } catch (error: any) {
        console.error('Admin data fetch error:', error);
        toast({
          title: "Admin Access Error",
          description: error.message || "Failed to fetch admin data",
          variant: "destructive"
        });
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [toast]);

  const handleExportData = async () => {
    setExportLoading(true);
    try {
      const response = await fetch('/api/export-data', {
        headers: { 
          Authorization: 'Bearer YOUR_ADMIN_TOKEN',
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new Error('Export failed');
      }
      
      const exportData = await response.json();
      
      // Download as JSON file
      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: 'application/json'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `theagencyiq-export-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      toast({
        title: "Export Complete",
        description: "Data exported successfully with gift certificates included"
      });
    } catch (error: any) {
      toast({
        title: "Export Failed",
        description: error.message || "Failed to export data",
        variant: "destructive"
      });
    } finally {
      setExportLoading(false);
    }
  };

  const getTotalGiftCertificates = () => {
    return users.reduce((total, user) => total + user.gifts.length, 0);
  };

  const getRedeemedGiftCertificates = () => {
    return users.reduce((total, user) => 
      total + user.gifts.filter(gift => gift.redeemed).length, 0
    );
  };

  const getTotalPosts = () => {
    return users.reduce((total, user) => total + user.posts.length, 0);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading admin dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Admin Dashboard</h1>
          <p className="text-gray-600 mt-2">System overview and data management</p>
        </div>
        <Button 
          onClick={handleExportData} 
          disabled={exportLoading}
          className="flex items-center gap-2"
        >
          <Download className="h-4 w-4" />
          {exportLoading ? 'Exporting...' : 'Export All Data'}
        </Button>
      </div>

      {/* Data Source Information */}
      {dataLocation && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5" />
              Data Sources
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="font-medium">User Data:</span>
                <Badge variant="outline" className="ml-2">{dataLocation.dataSource}</Badge>
              </div>
              <div>
                <span className="font-medium">Gift Certificates:</span>
                <Badge variant="outline" className="ml-2">{dataLocation.giftSource}</Badge>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tab Navigation */}
      <div className="flex space-x-1 rounded-lg bg-gray-100 p-1">
        {[
          { id: 'overview', label: 'System Overview', icon: Database },
          { id: 'certificates', label: 'Gift Certificate Tracker', icon: Activity }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 flex-1 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-white text-gray-900 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <>
          {/* Summary Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{users.length}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Gift Certificates</CardTitle>
            <Gift className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{getTotalGiftCertificates()}</div>
            <p className="text-xs text-muted-foreground">
              {getRedeemedGiftCertificates()} redeemed
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Posts</CardTitle>
            <Calendar className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{getTotalPosts()}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Plans</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              <div className="text-sm">
                Pro: {users.filter(u => u.plan === 'professional').length}
              </div>
              <div className="text-sm">
                Growth: {users.filter(u => u.plan === 'growth').length}
              </div>
              <div className="text-sm">
                Starter: {users.filter(u => u.plan === 'starter').length}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* User Data Table */}
      <Card>
        <CardHeader>
          <CardTitle>User Data with Gift Certificates</CardTitle>
          <CardDescription>
            Complete user overview including phone UID, subscription plans, and gift certificate redemptions
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse border border-gray-300">
              <thead>
                <tr className="bg-gray-50">
                  <th className="border border-gray-300 p-3 text-left">Phone (UID)</th>
                  <th className="border border-gray-300 p-3 text-left">Email</th>
                  <th className="border border-gray-300 p-3 text-left">Plan</th>
                  <th className="border border-gray-300 p-3 text-left">Posts</th>
                  <th className="border border-gray-300 p-3 text-left">Gift Certificates</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user, index) => (
                  <tr key={index} className="hover:bg-gray-50">
                    <td className="border border-gray-300 p-3 font-mono text-sm">
                      {user.phone || 'N/A'}
                    </td>
                    <td className="border border-gray-300 p-3">{user.email}</td>
                    <td className="border border-gray-300 p-3">
                      <Badge variant={
                        user.plan === 'professional' ? 'default' :
                        user.plan === 'growth' ? 'secondary' : 'outline'
                      }>
                        {user.plan}
                      </Badge>
                    </td>
                    <td className="border border-gray-300 p-3">
                      {user.posts.length} scheduled
                    </td>
                    <td className="border border-gray-300 p-3">
                      {user.gifts.length > 0 ? (
                        <div className="space-y-1">
                          {user.gifts.map((gift, giftIndex) => (
                            <div key={giftIndex} className="text-sm">
                              <Badge variant={gift.redeemed ? 'default' : 'outline'} className="mr-2">
                                {gift.code}
                              </Badge>
                              <span className="text-xs text-gray-600">
                                {gift.plan} - {gift.redeemed ? 'Redeemed' : 'Available'}
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <span className="text-gray-400">No certificates</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Gift Certificate Summary */}
      <Card>
        <CardHeader>
          <CardTitle>Gift Certificate Details</CardTitle>
          <CardDescription>
            All gift certificates in the system with redemption status
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {users.flatMap(user => 
              user.gifts.map(gift => ({
                ...gift,
                userEmail: user.email,
                userPhone: user.phone
              }))
            ).length > 0 ? (
              users.flatMap(user => 
                user.gifts.map(gift => ({
                  ...gift,
                  userEmail: user.email,
                  userPhone: user.phone
                }))
              ).map((gift, index) => (
                <div key={index} className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="flex items-center space-x-4">
                    <Badge variant={gift.redeemed ? 'default' : 'outline'}>
                      {gift.code}
                    </Badge>
                    <div>
                      <div className="font-medium">{gift.plan} Plan</div>
                      <div className="text-sm text-gray-600">
                        Created for: {gift.createdFor}
                      </div>
                      {gift.redeemed && (
                        <div className="text-sm text-gray-600">
                          Redeemed by: {gift.userEmail} ({gift.userPhone})
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`font-medium ${gift.redeemed ? 'text-green-600' : 'text-orange-600'}`}>
                      {gift.redeemed ? 'Redeemed' : 'Available'}
                    </div>
                    {gift.redeemedAt && (
                      <div className="text-sm text-gray-500">
                        {new Date(gift.redeemedAt).toLocaleDateString()}
                      </div>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                No gift certificates found in the system
              </div>
            )}
          </div>
        </CardContent>
      </Card>
        </>
      )}

      {/* Gift Certificate Tracker Tab */}
      {activeTab === 'certificates' && (
        <GiftCertificateTracker />
      )}
    </div>
  );
};

export default AdminDashboard;