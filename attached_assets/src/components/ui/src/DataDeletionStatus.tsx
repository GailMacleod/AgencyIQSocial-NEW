import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle, Clock, AlertCircle, Trash2 } from "lucide-react";

export default function DataDeletionStatus() {
  const [location] = useLocation();
  const [deletionCode, setDeletionCode] = useState<string | null>(null);
  const [status, setStatus] = useState<'processing' | 'completed' | 'error'>('processing');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    
    if (code) {
      setDeletionCode(code);
      
      // Parse confirmation code to determine status
      if (code.includes('processing_error') || code.includes('invalid_request') || code.includes('user_not_found')) {
        setStatus('error');
      } else if (code.startsWith('DEL_')) {
        setStatus('completed');
      }
    }
  }, [location]);

  const getStatusInfo = () => {
    switch (status) {
      case 'completed':
        return {
          icon: <CheckCircle className="h-8 w-8 text-green-500" />,
          title: "Data Deletion Completed",
          description: "Your data has been successfully removed from our systems",
          badgeText: "Completed",
          badgeVariant: "default" as const
        };
      case 'processing':
        return {
          icon: <Clock className="h-8 w-8 text-blue-500" />,
          title: "Data Deletion In Progress",
          description: "Your data deletion request is being processed",
          badgeText: "Processing",
          badgeVariant: "secondary" as const
        };
      case 'error':
        return {
          icon: <AlertCircle className="h-8 w-8 text-red-500" />,
          title: "Data Deletion Request Error",
          description: "There was an issue processing your data deletion request",
          badgeText: "Error",
          badgeVariant: "destructive" as const
        };
    }
  };

  const statusInfo = getStatusInfo();

  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4">
      <div className="max-w-2xl mx-auto">
        <div className="text-center mb-8">
          <Trash2 className="h-12 w-12 text-gray-600 mx-auto mb-4" />
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Data Deletion Status</h1>
          <p className="text-gray-600">Track your data deletion request status</p>
        </div>

        <Card>
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              {statusInfo.icon}
            </div>
            <CardTitle className="text-xl">{statusInfo.title}</CardTitle>
            <CardDescription>{statusInfo.description}</CardDescription>
            <div className="flex justify-center mt-4">
              <Badge variant={statusInfo.badgeVariant}>{statusInfo.badgeText}</Badge>
            </div>
          </CardHeader>
          
          <CardContent>
            {deletionCode && (
              <div className="bg-gray-50 p-4 rounded-lg mb-6">
                <h3 className="font-semibold text-sm text-gray-700 mb-2">Confirmation Code</h3>
                <code className="text-sm font-mono text-gray-900 bg-white px-2 py-1 rounded border">
                  {deletionCode}
                </code>
              </div>
            )}

            <div className="space-y-4">
              <div>
                <h3 className="font-semibold text-gray-900 mb-2">What Data Was Deleted</h3>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>• Social media platform connections (Facebook, Instagram, LinkedIn, etc.)</li>
                  <li>• Generated posts and content</li>
                  <li>• Brand purpose and strategy data</li>
                  <li>• Account information and preferences</li>
                  <li>• Analytics and performance data</li>
                </ul>
              </div>

              <div>
                <h3 className="font-semibold text-gray-900 mb-2">Data Retention Policy</h3>
                <p className="text-sm text-gray-600">
                  All personal data has been permanently removed from our systems in compliance with 
                  data protection regulations. This action cannot be undone.
                </p>
              </div>

              {status === 'error' && (
                <div className="bg-red-50 p-4 rounded-lg">
                  <h3 className="font-semibold text-red-800 mb-2">Need Help?</h3>
                  <p className="text-sm text-red-700">
                    If you continue to experience issues with your data deletion request, 
                    please contact our support team with your confirmation code.
                  </p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <div className="mt-8 text-center">
          <p className="text-sm text-gray-500">
            This page confirms compliance with Meta's data deletion requirements and applicable data protection laws.
          </p>
        </div>
      </div>
    </div>
  );
}