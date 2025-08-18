/**
 * Enhanced Session Loading Spinner with Retry Button
 * Addresses user's concern about missing retry button in spinner
 */

import { Button } from "@/components/ui/button";
import { AlertCircle, RefreshCw, Wifi, WifiOff } from "lucide-react";

interface SessionLoadingSpinnerProps {
  isEstablishing: boolean;
  isError: boolean;
  error: string | null;
  onRetry: () => void;
  className?: string;
}

export function SessionLoadingSpinner({ 
  isEstablishing, 
  isError, 
  error, 
  onRetry,
  className = ""
}: SessionLoadingSpinnerProps) {
  if (!isEstablishing && !isError) {
    return null;
  }

  if (isError) {
    const isAuthError = error?.includes('Authentication') || error?.includes('401');
    const isNetworkError = error?.includes('timeout') || error?.includes('Failed to fetch');
    
    return (
      <div className={`fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 ${className}`}>
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md mx-4 shadow-2xl">
          <div className="flex items-center space-x-3 mb-4">
            {isNetworkError ? (
              <WifiOff className="h-6 w-6 text-red-500" />
            ) : (
              <AlertCircle className="h-6 w-6 text-red-500" />
            )}
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              {isAuthError ? "Authentication Required" : "Session Error"}
            </h3>
          </div>
          
          <p className="text-gray-600 dark:text-gray-300 mb-6">
            {isAuthError ? 
              "Your session has expired. Please log in to continue." :
              error || "Failed to establish session. Please check your connection and try again."
            }
          </p>
          
          <div className="flex space-x-3">
            {isAuthError ? (
              <Button 
                onClick={() => window.location.href = '/api/login'}
                className="flex-1 bg-blue-600 hover:bg-blue-700"
              >
                Sign In
              </Button>
            ) : (
              <Button 
                onClick={onRetry}
                className="flex-1 bg-blue-600 hover:bg-blue-700"
                disabled={isEstablishing}
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${isEstablishing ? 'animate-spin' : ''}`} />
                Retry Connection
              </Button>
            )}
            
            <Button 
              variant="outline"
              onClick={() => window.location.reload()}
              className="flex-1"
            >
              Refresh Page
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // Loading state
  return (
    <div className={`fixed inset-0 bg-black bg-opacity-30 flex items-center justify-center z-50 ${className}`}>
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 flex flex-col items-center space-y-4 shadow-2xl">
        <div className="flex items-center space-x-3">
          <Wifi className="h-6 w-6 text-blue-500 animate-pulse" />
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
        </div>
        
        <div className="text-center">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
            Establishing Session
          </h3>
          <p className="text-gray-600 dark:text-gray-300">
            Connecting to TheAgencyIQ...
          </p>
        </div>
      </div>
    </div>
  );
}

export default SessionLoadingSpinner;