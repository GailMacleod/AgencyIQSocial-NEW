import { AlertCircle, CheckCircle2, RefreshCw, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { useTokenValidation } from '@/hooks/useTokenValidation';
import { useState } from 'react';
import { Link } from 'wouter';

export function TokenStatusBanner() {
  const { getValidationResults, validateAllTokens, isValidating } = useTokenValidation();
  const [isDismissed, setIsDismissed] = useState(false);
  const { validTokens, expiredTokens, needsAttention } = getValidationResults();

  // Don't show banner if dismissed or no issues
  if (isDismissed || !needsAttention) {
    return null;
  }

  const totalPlatforms = validTokens.length + expiredTokens.length;
  const validCount = validTokens.length;

  return (
    <Alert className="mb-4 border-orange-200 bg-orange-50 dark:border-orange-800 dark:bg-orange-950">
      <AlertCircle className="h-4 w-4 text-orange-600 dark:text-orange-400" />
      <AlertDescription>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-orange-800 dark:text-orange-200">
              Platform Authentication Issues
            </span>
            <Badge variant="outline" className="text-xs">
              {validCount}/{totalPlatforms} connected
            </Badge>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={validateAllTokens}
              disabled={isValidating}
              className="h-8 text-xs"
            >
              {isValidating ? (
                <>
                  <RefreshCw className="h-3 w-3 animate-spin mr-1" />
                  Checking...
                </>
              ) : (
                <>
                  <RefreshCw className="h-3 w-3 mr-1" />
                  Refresh
                </>
              )}
            </Button>
            <Link href="/connect-platforms">
              <Button size="sm" className="h-8 text-xs">
                Fix Connections
              </Button>
            </Link>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsDismissed(true)}
              className="h-8 w-8 p-0"
            >
              <X className="h-3 w-3" />
            </Button>
          </div>
        </div>
        
        {expiredTokens.length > 0 && (
          <div className="mt-2 text-sm text-orange-700 dark:text-orange-300">
            <strong>Expired platforms:</strong> {expiredTokens.map(token => token.platform).join(', ')}
            <br />
            <span className="text-xs">Your posts won't appear on these platforms until reconnected.</span>
          </div>
        )}
      </AlertDescription>
    </Alert>
  );
}

export function TokenStatusIndicator() {
  const { getValidationResults, isLoading } = useTokenValidation();
  const { validTokens, expiredTokens, needsAttention } = getValidationResults();

  if (isLoading) {
    return (
      <div className="flex items-center gap-2">
        <RefreshCw className="h-4 w-4 animate-spin text-gray-500" />
        <span className="text-sm text-gray-500">Checking connections...</span>
      </div>
    );
  }

  const totalPlatforms = validTokens.length + expiredTokens.length;
  const validCount = validTokens.length;

  return (
    <div className="flex items-center gap-2">
      {needsAttention ? (
        <AlertCircle className="h-4 w-4 text-orange-500" />
      ) : (
        <CheckCircle2 className="h-4 w-4 text-green-500" />
      )}
      <span className="text-sm">
        {validCount}/{totalPlatforms} platforms connected
      </span>
      {needsAttention && (
        <Badge variant="destructive" className="text-xs">
          {expiredTokens.length} expired
        </Badge>
      )}
    </div>
  );
}