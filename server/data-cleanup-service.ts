/**
 * DATA CLEANUP SERVICE
 * Automated data cleanup and quota reconciliation system
 * Handles archiving, quota corrections, and monitoring
 */

import { db } from './db';
import { sql } from 'drizzle-orm';
import fs from 'fs/promises';

interface CleanupResult {
  success: boolean;
  archived_posts: number;
  archived_certificates: number;
  quota_corrections: number;
  errors: string[];
  details: any;
}

interface QuotaAnomalyAlert {
  user_id: string;
  email: string;
  total_posts: number;
  remaining_posts: number;
  anomaly_type: string;
  alert_level: 'warning' | 'critical';
}

export class DataCleanupService {
  
  /**
   * Comprehensive data cleanup and quota reconciliation
   * Archives excess posts, corrects quota discrepancies, cleans certificates
   */
  static async performDataCleanup(userId?: string): Promise<CleanupResult> {
    const result: CleanupResult = {
      success: false,
      archived_posts: 0,
      archived_certificates: 0,
      quota_corrections: 0,
      errors: [],
      details: {}
    };

    try {
      console.log('🧹 Starting comprehensive data cleanup...');

      // Archive excess posts (older than 6 months or exceeding quotas)
      const archiveResult = await this.archiveExcessPosts(userId);
      result.archived_posts = archiveResult.archived_count;
      result.details.post_archiving = archiveResult;

      // Archive redeemed gift certificates
      const certResult = await this.archiveRedeemedCertificates();
      result.archived_certificates = certResult.archived_count;
      result.details.certificate_archiving = certResult;

      // Correct quota discrepancies
      const quotaResult = await this.correctQuotaDiscrepancies(userId);
      result.quota_corrections = quotaResult.corrections_made;
      result.details.quota_corrections = quotaResult;

      // Remove orphaned data
      await this.removeOrphanedData();

      // Generate cleanup report
      await this.generateCleanupReport(result);

      result.success = true;
      console.log('✅ Data cleanup completed successfully');
      return result;

    } catch (error) {
      console.error('❌ Data cleanup failed:', error);
      result.errors.push(error instanceof Error ? error.message : 'Unknown error');
      return result;
    }
  }

  /**
   * Archive posts older than 6 months or exceeding subscription quotas
   */
  private static async archiveExcessPosts(userId?: string): Promise<any> {
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const userFilter = userId ? `AND user_id = '${userId}'` : '';
    
    // Archive old posts
    const archiveQuery = `
      INSERT INTO posts_archive (
        id, user_id, platform, content, status, published_at, error_log, scheduled_for,
        created_at, analytics, ai_recommendation, subscription_cycle, video_url, has_video,
        video_metadata, updated_at, video_approved, video_data, approved_at, archive_reason
      )
      SELECT 
        id, user_id, platform, content, status, published_at, error_log, scheduled_for,
        created_at, analytics, ai_recommendation, subscription_cycle, video_url, has_video,
        video_metadata, updated_at, video_approved, video_data, approved_at,
        'Automated cleanup: Posts older than 6 months'
      FROM posts 
      WHERE created_at < $1 ${userFilter}
    `;

    const archivedRows = await db.execute(sql.raw(archiveQuery, [sixMonthsAgo]));
    
    // Delete archived posts
    await db.execute(sql.raw(`
      DELETE FROM posts 
      WHERE created_at < $1 ${userFilter}
    `, [sixMonthsAgo]));

    return {
      archived_count: archivedRows.rowCount || 0,
      cutoff_date: sixMonthsAgo.toISOString()
    };
  }

  /**
   * Archive redeemed gift certificates
   */
  private static async archiveRedeemedCertificates(): Promise<any> {
    // Archive redeemed certificates
    const archiveResult = await db.execute(sql.raw(`
      INSERT INTO gift_certificates_archive (id, code, plan, redeemed_by, redeemed_at, created_at, archive_reason)
      SELECT id, code, plan, redeemed_by, redeemed_at, created_at, 'Automated cleanup: Redeemed certificates'
      FROM gift_certificates 
      WHERE redeemed_at IS NOT NULL
    `));

    // Remove from main table
    await db.execute(sql.raw(`
      DELETE FROM gift_certificates WHERE redeemed_at IS NOT NULL
    `));

    return {
      archived_count: archiveResult.rowCount || 0
    };
  }

  /**
   * Correct quota discrepancies across all users
   */
  private static async correctQuotaDiscrepancies(userId?: string): Promise<any> {
    const userFilter = userId ? `WHERE u.id = '${userId}'` : '';
    
    const discrepancies = await db.execute(sql.raw(`
      SELECT 
        u.id,
        u.email,
        u.total_posts,
        u.remaining_posts,
        u.subscription_plan,
        COALESCE(p.actual_published, 0) as actual_published,
        CASE 
          WHEN u.subscription_plan = 'starter' THEN 10
          WHEN u.subscription_plan = 'growth' THEN 20
          WHEN u.subscription_plan = 'professional' THEN 30
          ELSE 10
        END as plan_quota,
        CASE 
          WHEN u.subscription_plan = 'starter' THEN 10
          WHEN u.subscription_plan = 'growth' THEN 20
          WHEN u.subscription_plan = 'professional' THEN 30
          ELSE 10
        END - COALESCE(p.actual_published, 0) as correct_remaining
      FROM users u
      LEFT JOIN (
        SELECT user_id, COUNT(*) as actual_published
        FROM posts
        WHERE status = 'published'
        GROUP BY user_id
      ) p ON u.id = p.user_id
      ${userFilter}
    `));

    let corrections_made = 0;

    for (const row of discrepancies.rows) {
      const user = row as any;
      
      if (user.remaining_posts !== user.correct_remaining) {
        // Log quota correction
        await db.execute(sql.raw(`
          INSERT INTO quota_history (user_id, previous_total, new_total, previous_remaining, new_remaining, change_reason)
          VALUES ($1, $2, $3, $4, $5, 'Automated cleanup: Quota discrepancy correction')
        `, [user.id, user.total_posts, user.plan_quota, user.remaining_posts, user.correct_remaining]));

        // Update user quota
        await db.execute(sql.raw(`
          UPDATE users 
          SET total_posts = $1, remaining_posts = $2, updated_at = CURRENT_TIMESTAMP
          WHERE id = $3
        `, [user.plan_quota, user.correct_remaining, user.id]));

        corrections_made++;
      }
    }

    return { corrections_made, total_users_checked: discrepancies.rowCount };
  }

  /**
   * Remove orphaned data
   */
  private static async removeOrphanedData(): Promise<void> {
    // Remove posts without valid user_id
    await db.execute(sql.raw(`
      DELETE FROM posts 
      WHERE user_id NOT IN (SELECT id FROM users)
    `));

    // Remove platform connections without valid user_id
    await db.execute(sql.raw(`
      DELETE FROM platform_connections 
      WHERE user_id NOT IN (SELECT id FROM users)
    `));
  }

  /**
   * Generate cleanup report
   */
  private static async generateCleanupReport(result: CleanupResult): Promise<void> {
    const report = {
      timestamp: new Date().toISOString(),
      cleanup_summary: {
        archived_posts: result.archived_posts,
        archived_certificates: result.archived_certificates,
        quota_corrections: result.quota_corrections,
        success: result.success
      },
      details: result.details,
      errors: result.errors
    };

    await fs.mkdir('data', { recursive: true });
    await fs.writeFile('data/cleanup-report.json', JSON.stringify(report, null, 2));
    
    const logEntry = `[${new Date().toISOString()}] DATA CLEANUP COMPLETED - Posts: ${result.archived_posts}, Certificates: ${result.archived_certificates}, Quota Corrections: ${result.quota_corrections}\n`;
    await fs.appendFile('data/quota-debug.log', logEntry);
  }

  /**
   * Monitor for quota anomalies
   */
  static async detectQuotaAnomalies(): Promise<QuotaAnomalyAlert[]> {
    const anomalies = await db.execute(sql.raw(`
      SELECT 
        u.id as user_id,
        u.email,
        u.total_posts,
        u.remaining_posts,
        u.subscription_plan,
        CASE 
          WHEN u.subscription_plan = 'starter' THEN 10
          WHEN u.subscription_plan = 'growth' THEN 20
          WHEN u.subscription_plan = 'professional' THEN 30
          ELSE 10
        END as plan_quota
      FROM users u
      WHERE 
        u.total_posts > CASE 
          WHEN u.subscription_plan = 'starter' THEN 10
          WHEN u.subscription_plan = 'growth' THEN 20
          WHEN u.subscription_plan = 'professional' THEN 30
          ELSE 10
        END
        OR u.remaining_posts < 0
        OR u.remaining_posts > CASE 
          WHEN u.subscription_plan = 'starter' THEN 10
          WHEN u.subscription_plan = 'growth' THEN 20
          WHEN u.subscription_plan = 'professional' THEN 30
          ELSE 10
        END
    `));

    return anomalies.rows.map((row: any) => ({
      user_id: row.user_id,
      email: row.email,
      total_posts: row.total_posts,
      remaining_posts: row.remaining_posts,
      anomaly_type: row.total_posts > row.plan_quota ? 'quota_exceeded' : 'invalid_remaining',
      alert_level: row.total_posts > row.plan_quota + 10 ? 'critical' : 'warning'
    }));
  }

  /**
   * Get real-time quota dashboard data
   */
  static async getQuotaDashboard(): Promise<any> {
    const dashboard = await db.execute(sql.raw(`
      SELECT 
        u.id,
        u.email,
        u.subscription_plan,
        u.total_posts,
        u.remaining_posts,
        COALESCE(p.published_count, 0) as actual_published,
        COALESCE(p.approved_count, 0) as approved_pending,
        COALESCE(p.draft_count, 0) as drafts,
        CASE 
          WHEN u.subscription_plan = 'starter' THEN 10
          WHEN u.subscription_plan = 'growth' THEN 20
          WHEN u.subscription_plan = 'professional' THEN 30
          ELSE 10
        END as plan_quota,
        ROUND(
          (COALESCE(p.published_count, 0) * 100.0 / CASE 
            WHEN u.subscription_plan = 'starter' THEN 10
            WHEN u.subscription_plan = 'growth' THEN 20
            WHEN u.subscription_plan = 'professional' THEN 30
            ELSE 10
          END), 2
        ) as quota_usage_percentage
      FROM users u
      LEFT JOIN (
        SELECT 
          user_id,
          COUNT(*) FILTER (WHERE status = 'published') as published_count,
          COUNT(*) FILTER (WHERE status = 'approved') as approved_count,
          COUNT(*) FILTER (WHERE status = 'draft') as draft_count
        FROM posts
        GROUP BY user_id
      ) p ON u.id = p.user_id
      ORDER BY quota_usage_percentage DESC
    `));

    return {
      users: dashboard.rows,
      summary: {
        total_users: dashboard.rowCount,
        anomalies: await this.detectQuotaAnomalies()
      }
    };
  }
}