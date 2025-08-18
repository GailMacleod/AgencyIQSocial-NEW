/**
 * ENHANCED CANCELLATION HANDLER - CEO-APPROVED FIX
 * Addresses all architectural fractures identified in comprehensive app review
 * Async/parallel processing, full error aggregation, complete integration cleanup
 */

import Stripe from 'stripe';
import { storage } from '../storage';
import { quotaManager } from './QuotaManager';
import { postingQueue } from './PostingQueue';
import { DataCleanupService } from './DataCleanupService';

interface CancellationResult {
  cancelled: string[];
  errors: string[];
  cleanup: any;
  sessionsDestroyed: boolean;
  quotaReset: boolean;
  oauthRevoked: number;
  autoPostStopped: boolean;
}

export class EnhancedCancellationHandler {
  private stripe: Stripe | null;

  constructor(stripe: Stripe | null = null) {
    this.stripe = stripe;
  }

  /**
   * Enhanced Cancellation Handler - CEO-Approved Fix
   * Async/parallel cancels, full error aggregation, ties to app integration
   * Fixes: session destroy, quota reset, auto-post stop, OAuth revoke
   */
  async handleSubscriptionCancellation(userId: number, req?: any): Promise<CancellationResult> {
    const user = await storage.getUser(userId);
    if (!user) {
      throw new Error('User not found');
    }

    console.log(`🔴 Comprehensive cancellation for ${user.email} (ID: ${userId})`);

    let allCancelled: string[] = [];
    let errors: string[] = [];
    let cleanup: any = null;
    let sessionsDestroyed = false;
    let quotaReset = false;
    let oauthRevoked = 0;
    let autoPostStopped = false;

    // PARALLEL STRIPE CANCELLATION: Primary + Customer Subscriptions
    if (this.stripe) {
      try {
        // Parallel: Cancel primary + all customer subs
        const [primaryResult, customerSubsResult] = await Promise.allSettled([
          user.stripeSubscriptionId ? 
            this.stripe.subscriptions.cancel(user.stripeSubscriptionId, { 
              prorate: false, 
              invoice_now: false 
            }) : 
            Promise.resolve(null),
          user.stripeCustomerId ? 
            this.stripe.subscriptions.list({ 
              customer: user.stripeCustomerId, 
              status: 'active', 
              limit: 100 
            }) : 
            Promise.resolve({ data: [] })
        ]);

        // Process primary subscription cancellation
        if (primaryResult.status === 'fulfilled' && primaryResult.value) {
          allCancelled.push(primaryResult.value.id);
          console.log(`✅ Primary subscription cancelled: ${primaryResult.value.id}`);
        }

        // Process customer subscriptions cancellation
        if (customerSubsResult.status === 'fulfilled') {
          await Promise.all(customerSubsResult.value.data.map(async (sub: any) => {
            try {
              const cancelled = await this.stripe!.subscriptions.cancel(sub.id, { 
                prorate: false, 
                invoice_now: false 
              });
              allCancelled.push(cancelled.id);
              console.log(`✅ Customer subscription cancelled: ${cancelled.id}`);
            } catch (subErr: any) {
              errors.push(`Sub ${sub.id}: ${subErr.message}`);
              console.error(`❌ Failed to cancel subscription ${sub.id}:`, subErr.message);
            }
          }));
        } else if (customerSubsResult.reason) {
          errors.push(`Customer list: ${customerSubsResult.reason.message}`);
        }

        // PAGINATED EMAIL LOOKUP: Handle >100 customers
        if (user.email) {
          let hasMore = true;
          let startingAfter: string | undefined = undefined;
          
          while (hasMore) {
            try {
              const customers = await this.stripe.customers.list({ 
                email: user.email, 
                limit: 100, 
                starting_after: startingAfter 
              });
              
              hasMore = customers.has_more;
              startingAfter = customers.data[customers.data.length - 1]?.id;

              for (const cust of customers.data) {
                const subs = await this.stripe.subscriptions.list({ 
                  customer: cust.id, 
                  status: 'active', 
                  limit: 100 
                });
                
                await Promise.all(subs.data.map(async (sub: any) => {
                  try {
                    const cancelled = await this.stripe!.subscriptions.cancel(sub.id, { 
                      prorate: false, 
                      invoice_now: false 
                    });
                    allCancelled.push(cancelled.id);
                    console.log(`✅ Email-based subscription cancelled: ${cancelled.id}`);
                  } catch (subErr: any) {
                    errors.push(`Email sub ${sub.id}: ${subErr.message}`);
                    console.error(`❌ Failed to cancel email subscription ${sub.id}:`, subErr.message);
                  }
                }));
              }
            } catch (emailErr: any) {
              errors.push(`Email pagination: ${emailErr.message}`);
              break; // Exit pagination loop on error
            }
          }
        }
      } catch (stripeErr: any) {
        errors.push(`Stripe overall: ${stripeErr.message}`);
        console.error('❌ Stripe cancellation failed:', stripeErr.message);
      }
    } else {
      errors.push('Stripe not initialized');
      console.error('❌ Stripe not initialized for cancellation');
    }

    // INTEGRATED CLEANUP: Quotas, Auto-Post, OAuth, Sessions
    try {
      // 1. Reset Quotas - prevents post-cancel resource abuse
      await quotaManager.resetUserQuota(userId);
      quotaReset = true;
      console.log(`✅ Quota reset for user ${userId}`);
    } catch (quotaErr: any) {
      errors.push(`Quota reset: ${quotaErr.message}`);
      console.error('❌ Quota reset failed:', quotaErr.message);
    }

    try {
      // 2. Emergency Stop Auto-Posts - prevents scheduled posting after cancellation
      postingQueue.emergencyStop();
      autoPostStopped = true;
      console.log(`✅ Auto-posting stopped for all queues`);
    } catch (postErr: any) {
      errors.push(`Auto-post stop: ${postErr.message}`);
      console.error('❌ Auto-post stop failed:', postErr.message);
    }

    try {
      // 3. Revoke OAuth Tokens - security compliance
      const connections = await storage.getPlatformConnectionsByUser(userId);
      await Promise.all(connections.map(async (conn: any) => {
        try {
          await this.revokeOAuthToken(conn);
          oauthRevoked++;
          console.log(`✅ OAuth token revoked for ${conn.platform}`);
        } catch (oauthErr: any) {
          errors.push(`OAuth ${conn.platform}: ${oauthErr.message}`);
          console.error(`❌ OAuth revocation failed for ${conn.platform}:`, oauthErr.message);
        }
      }));
    } catch (oauthErr: any) {
      errors.push(`OAuth revocation: ${oauthErr.message}`);
      console.error('❌ OAuth connection retrieval failed:', oauthErr.message);
    }

    try {
      // 4. Session Destruction - prevents stale session data
      if (req && req.session) {
        req.session.destroy();
        sessionsDestroyed = true;
        console.log(`✅ Session destroyed for user ${userId}`);
      }
    } catch (sessionErr: any) {
      errors.push(`Session destroy: ${sessionErr.message}`);
      console.error('❌ Session destruction failed:', sessionErr.message);
    }

    try {
      // 5. Comprehensive Data Cleanup - remove drafts/videos/schedules
      cleanup = await DataCleanupService.performCompleteDataCleanup(userId, user.email);
      console.log(`✅ Data cleanup completed for user ${userId}`);
    } catch (cleanupErr: any) {
      errors.push(`Data cleanup: ${cleanupErr.message}`);
      console.error('❌ Data cleanup failed:', cleanupErr.message);
    }

    try {
      // 6. Update User Record - final database state
      await storage.updateUser(userId, { 
        subscriptionPlan: 'cancelled', 
        stripeSubscriptionId: null, 
        remainingPosts: 0, 
        totalPosts: 0, 
        subscriptionActive: false 
      });
      console.log(`✅ User record updated for cancellation: ${userId}`);
    } catch (updateErr: any) {
      errors.push(`User update: ${updateErr.message}`);
      console.error('❌ User record update failed:', updateErr.message);
    }

    const result: CancellationResult = { 
      cancelled: allCancelled, 
      errors, 
      cleanup,
      sessionsDestroyed,
      quotaReset,
      oauthRevoked,
      autoPostStopped
    };

    console.log(`🏁 Cancellation completed for user ${userId}:`);
    console.log(`   Subscriptions cancelled: ${allCancelled.length}`);
    console.log(`   OAuth tokens revoked: ${oauthRevoked}`);
    console.log(`   Errors encountered: ${errors.length}`);
    console.log(`   Sessions destroyed: ${sessionsDestroyed ? 'Yes' : 'No'}`);
    console.log(`   Quota reset: ${quotaReset ? 'Yes' : 'No'}`);
    console.log(`   Auto-posting stopped: ${autoPostStopped ? 'Yes' : 'No'}`);

    return result;
  }

  /**
   * Helper: Revoke OAuth per platform
   * Platform-specific token revocation with proper endpoints
   */
  private async revokeOAuthToken(connection: any): Promise<void> {
    if (!connection.accessToken) {
      console.log(`⚠️ No access token to revoke for ${connection.platform}`);
      return;
    }

    const platformEndpoints = {
      google: 'https://oauth2.googleapis.com/revoke',
      facebook: 'https://graph.facebook.com/me/permissions',
      instagram: 'https://graph.facebook.com/me/permissions',
      linkedin: 'https://www.linkedin.com/oauth/v2/revoke',
      x: 'https://api.twitter.com/2/oauth2/revoke',
      youtube: 'https://oauth2.googleapis.com/revoke'
    };

    const endpoint = platformEndpoints[connection.platform as keyof typeof platformEndpoints];
    if (!endpoint) {
      throw new Error(`No revocation endpoint configured for platform: ${connection.platform}`);
    }

    try {
      let response;
      
      switch (connection.platform) {
        case 'google':
        case 'youtube':
          // Google/YouTube: POST with token parameter
          response = await fetch(`${endpoint}?token=${connection.accessToken}`, { 
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
          });
          break;
          
        case 'facebook':
        case 'instagram':
          // Facebook/Instagram: DELETE to revoke permissions
          response = await fetch(`${endpoint}?access_token=${connection.accessToken}`, { 
            method: 'DELETE' 
          });
          break;
          
        case 'linkedin':
          // LinkedIn: POST with token parameter
          response = await fetch(`${endpoint}?token=${connection.accessToken}`, { 
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
          });
          break;
          
        case 'x':
          // X (Twitter): POST with token parameter
          response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `token=${connection.accessToken}`
          });
          break;
          
        default:
          throw new Error(`Unsupported platform for token revocation: ${connection.platform}`);
      }

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      console.log(`✅ OAuth token revoked for ${connection.platform}: ${response.status}`);
    } catch (error: any) {
      console.error(`❌ Failed to revoke OAuth token for ${connection.platform}:`, error.message);
      // Continue on failure - log and continue rather than throwing
      throw error;
    }
  }
}

export default EnhancedCancellationHandler;