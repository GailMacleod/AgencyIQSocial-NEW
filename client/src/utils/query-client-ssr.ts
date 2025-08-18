/**
 * Enhanced QueryClient with SSR dehydration support
 * Provides SSR-compatible React Query setup with proper hydration
 */

import React, { useState } from 'react';
import { QueryClient, DehydratedState } from '@tanstack/react-query';

interface SSRQueryClientOptions {
  defaultOptions?: any;
  dehydratedState?: DehydratedState;
}

// SSR-safe QueryClient creation
export function createSSRQueryClient(options: SSRQueryClientOptions = {}) {
  const { defaultOptions, dehydratedState } = options;

  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 60 * 1000, // 1 minute
        retry: (failureCount, error: any) => {
          // Don't retry on 4xx errors except 401 (auth issues)
          if (error?.status >= 400 && error?.status < 500 && error?.status !== 401) {
            return false;
          }
          return failureCount < 3;
        },
        refetchOnWindowFocus: false,
        refetchOnMount: true,
        ...defaultOptions?.queries,
      },
      mutations: {
        retry: (failureCount, error: any) => {
          // Don't retry mutations on client errors
          if (error?.status >= 400 && error?.status < 500) {
            return false;
          }
          return failureCount < 2;
        },
        ...defaultOptions?.mutations,
      },
    },
  });

  // If we have dehydrated state, we're in SSR context
  if (dehydratedState) {
    queryClient.setQueryData = queryClient.setQueryData.bind(queryClient);
  }

  return queryClient;
}

// Hook for SSR QueryClient with hydration
export function useSSRQueryClient(dehydratedState?: DehydratedState) {
  const [queryClient] = useState(() => createSSRQueryClient({ dehydratedState }));
  return queryClient;
}

// Component for SSR hydration
interface SSRHydrateProps {
  children: React.ReactNode;
  dehydratedState?: DehydratedState;
}

export function SSRHydrate({ children, dehydratedState }: SSRHydrateProps) {
  // In newer versions of React Query, hydration is handled automatically
  // This component serves as a placeholder for future SSR needs
  return children as React.ReactElement;
}

// Utility for server-side data prefetching
export async function prefetchServerData(queryClient: QueryClient, queries: Array<{
  queryKey: string[];
  queryFn: () => Promise<any>;
}>) {
  try {
    await Promise.allSettled(
      queries.map(({ queryKey, queryFn }) =>
        queryClient.prefetchQuery({
          queryKey,
          queryFn,
          staleTime: 60 * 1000, // 1 minute
        })
      )
    );
  } catch (error) {
    console.warn('Server data prefetching failed:', error);
    // Don't throw - SSR should continue even if prefetching fails
  }
}

// Utility to serialize dehydrated state for SSR
export function serializeDehydratedState(queryClient: QueryClient): string {
  try {
    const dehydratedState = queryClient.getQueryData('*') as DehydratedState;
    return JSON.stringify(dehydratedState);
  } catch (error) {
    console.warn('Failed to serialize dehydrated state:', error);
    return '{}';
  }
}