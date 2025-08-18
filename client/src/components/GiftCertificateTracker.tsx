import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useQuery } from "@tanstack/react-query";
import { 
  Gift, 
  Calendar, 
  User, 
  Activity, 
  CheckCircle, 
  XCircle, 
  Eye,
  AlertCircle,
  Clock
} from "lucide-react";

interface GiftCertificate {
  id: number;
  code: string;
  plan: string;
  isUsed: boolean;
  createdFor: string;
  createdBy: number | null;
  redeemedBy: number | null;
  createdAt: string;
  redeemedAt: string | null;
}

interface GiftCertificateActionLog {
  id: number;
  certificateId: number;
  certificateCode: string;
  actionType: string;
  actionBy: number | null;
  actionByEmail: string | null;
  actionDetails: any;
  ipAddress: string | null;
  userAgent: string | null;
  sessionId: string | null;
  success: boolean;
  errorMessage: string | null;
  createdAt: string;
}

interface GiftCertificateData {
  createdCertificates: GiftCertificate[];
  redeemedCertificates: GiftCertificate[];
  actionLogs: GiftCertificateActionLog[];
  summary: {
    totalCreated: number;
    totalRedeemed: number;
    totalActions: number;
  };
}

export default function GiftCertificateTracker() {
  const [activeTab, setActiveTab] = useState<'overview' | 'created' | 'redeemed' | 'logs'>('overview');

  const { data: certificateData, isLoading, error } = useQuery<GiftCertificateData>({
    queryKey: ['/api/my-gift-certificate-actions'],
    retry: 3,
    refetchOnWindowFocus: true,
  });

  const getActionIcon = (actionType: string) => {
    switch (actionType) {
      case 'created':
        return <Gift className="h-4 w-4 text-green-600" />;
      case 'redeemed':
        return <CheckCircle className="h-4 w-4 text-blue-600" />;
      case 'viewed':
        return <Eye className="h-4 w-4 text-gray-600" />;
      case 'attempted_redeem':
        return <AlertCircle className="h-4 w-4 text-red-600" />;
      default:
        return <Activity className="h-4 w-4 text-gray-600" />;
    }
  };

  const getActionColor = (actionType: string, success: boolean) => {
    if (!success) return 'bg-red-100 text-red-800';
    switch (actionType) {
      case 'created':
        return 'bg-green-100 text-green-800';
      case 'redeemed':
        return 'bg-blue-100 text-blue-800';
      case 'viewed':
        return 'bg-gray-100 text-gray-800';
      case 'attempted_redeem':
        return 'bg-orange-100 text-orange-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-AU', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getPlanColor = (plan: string) => {
    switch (plan.toLowerCase()) {
      case 'professional':
        return 'bg-purple-100 text-purple-800';
      case 'growth':
        return 'bg-blue-100 text-blue-800';
      case 'starter':
        return 'bg-green-100 text-green-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Gift className="h-5 w-5" />
            Gift Certificate Tracker
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Gift className="h-5 w-5" />
            Gift Certificate Tracker
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <XCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
            <p className="text-gray-600">Unable to load gift certificate data</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const { createdCertificates, redeemedCertificates, actionLogs, summary } = certificateData || {
    createdCertificates: [],
    redeemedCertificates: [],
    actionLogs: [],
    summary: { totalCreated: 0, totalRedeemed: 0, totalActions: 0 }
  };

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Created</p>
                <p className="text-2xl font-bold text-green-600">{summary.totalCreated}</p>
              </div>
              <Gift className="h-8 w-8 text-green-600" />
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Redeemed</p>
                <p className="text-2xl font-bold text-blue-600">{summary.totalRedeemed}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Actions</p>
                <p className="text-2xl font-bold text-purple-600">{summary.totalActions}</p>
              </div>
              <Activity className="h-8 w-8 text-purple-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tab Navigation */}
      <div className="flex space-x-1 rounded-lg bg-gray-100 p-1">
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'created', label: 'Created' },
          { id: 'redeemed', label: 'Redeemed' },
          { id: 'logs', label: 'Activity Log' }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex-1 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-white text-gray-900 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <Card>
        <CardHeader>
          <CardTitle className="capitalize">{activeTab} Details</CardTitle>
        </CardHeader>
        <CardContent>
          {activeTab === 'overview' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h3 className="font-medium text-gray-900 mb-2">Recent Created Certificates</h3>
                  {createdCertificates.slice(0, 3).map((cert) => (
                    <div key={cert.id} className="flex items-center justify-between py-2">
                      <div>
                        <p className="font-mono text-sm">{cert.code}</p>
                        <p className="text-xs text-gray-500">{formatDate(cert.createdAt)}</p>
                      </div>
                      <Badge className={getPlanColor(cert.plan)}>{cert.plan}</Badge>
                    </div>
                  ))}
                </div>
                
                <div>
                  <h3 className="font-medium text-gray-900 mb-2">Recent Activity</h3>
                  {actionLogs.slice(0, 3).map((log) => (
                    <div key={log.id} className="flex items-center gap-2 py-2">
                      {getActionIcon(log.actionType)}
                      <div className="flex-1">
                        <p className="text-sm">{log.certificateCode}</p>
                        <p className="text-xs text-gray-500">{formatDate(log.createdAt)}</p>
                      </div>
                      <Badge className={getActionColor(log.actionType, log.success)}>
                        {log.actionType.replace('_', ' ')}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'created' && (
            <div className="space-y-4">
              {createdCertificates.length === 0 ? (
                <div className="text-center py-8">
                  <Gift className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-600">No certificates created yet</p>
                </div>
              ) : (
                createdCertificates.map((cert) => (
                  <div key={cert.id} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center gap-3">
                      <Gift className="h-5 w-5 text-green-600" />
                      <div>
                        <p className="font-mono font-medium">{cert.code}</p>
                        <p className="text-sm text-gray-600">Created for: {cert.createdFor}</p>
                        <p className="text-xs text-gray-500">{formatDate(cert.createdAt)}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={getPlanColor(cert.plan)}>{cert.plan}</Badge>
                      <Badge variant={cert.isUsed ? "default" : "secondary"}>
                        {cert.isUsed ? "Redeemed" : "Available"}
                      </Badge>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'redeemed' && (
            <div className="space-y-4">
              {redeemedCertificates.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-600">No certificates redeemed yet</p>
                </div>
              ) : (
                redeemedCertificates.map((cert) => (
                  <div key={cert.id} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center gap-3">
                      <CheckCircle className="h-5 w-5 text-blue-600" />
                      <div>
                        <p className="font-mono font-medium">{cert.code}</p>
                        <p className="text-sm text-gray-600">Originally created for: {cert.createdFor}</p>
                        <p className="text-xs text-gray-500">
                          Redeemed: {cert.redeemedAt ? formatDate(cert.redeemedAt) : 'Unknown'}
                        </p>
                      </div>
                    </div>
                    <Badge className={getPlanColor(cert.plan)}>{cert.plan}</Badge>
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="space-y-4">
              {actionLogs.length === 0 ? (
                <div className="text-center py-8">
                  <Activity className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-600">No activity logged yet</p>
                </div>
              ) : (
                actionLogs.map((log) => (
                  <div key={log.id} className="flex items-start gap-3 p-4 border rounded-lg">
                    {getActionIcon(log.actionType)}
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-2">
                        <p className="font-mono text-sm">{log.certificateCode}</p>
                        <div className="flex items-center gap-2">
                          <Badge className={getActionColor(log.actionType, log.success)}>
                            {log.actionType.replace('_', ' ')}
                          </Badge>
                          {log.success ? (
                            <CheckCircle className="h-4 w-4 text-green-600" />
                          ) : (
                            <XCircle className="h-4 w-4 text-red-600" />
                          )}
                        </div>
                      </div>
                      <p className="text-sm text-gray-600 mb-1">
                        {log.actionByEmail || 'System action'}
                      </p>
                      <p className="text-xs text-gray-500 flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatDate(log.createdAt)}
                      </p>
                      {log.errorMessage && (
                        <p className="text-xs text-red-600 mt-1">{log.errorMessage}</p>
                      )}
                      {log.actionDetails && (
                        <div className="mt-2 p-2 bg-gray-50 rounded text-xs">
                          <pre>{JSON.stringify(log.actionDetails, null, 2)}</pre>
                        </div>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}