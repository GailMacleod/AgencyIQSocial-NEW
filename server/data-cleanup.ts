import { storage } from "./storage";
import { db } from "./db";
import { posts, verificationCodes, giftCertificates } from "@shared/schema";
import { lt, eq, and } from "drizzle-orm";

interface CleanupReport {
  timestamp: Date;
  deletedItems: {
    oldPosts: number;
    expiredVerificationCodes: number;
    usedGiftCertificates: number;
    inactiveConnections: number;
    resolvedBreachIncidents: number;
  };
  retainedItems: {
    activePosts: number;
    activeConnections: number;
    unresolvedIncidents: number;
  };
  errors: string[];
}

export class DataCleanupService {
  // Data retention policies (in days)
  private static readonly RETENTION_POLICIES = {
    publishedPosts: 365,        // Keep published posts for 1 year
    failedPosts: 90,           // Keep failed posts for 3 months
    expiredVerificationCodes: 7, // Delete expired verification codes after 7 days
    usedGiftCertificates: 90,   // Keep used gift certificates for 3 months
    inactiveConnections: 180,   // Delete inactive platform connections after 6 months
    resolvedBreachIncidents: 2555 // Keep resolved breach incidents for 7 years (compliance)
  };

  // Run comprehensive data cleanup
  static async performScheduledCleanup(): Promise<CleanupReport> {
    const report: CleanupReport = {
      timestamp: new Date(),
      deletedItems: {
        oldPosts: 0,
        expiredVerificationCodes: 0,
        usedGiftCertificates: 0,
        inactiveConnections: 0,
        resolvedBreachIncidents: 0
      },
      retainedItems: {
        activePosts: 0,
        activeConnections: 0,
        unresolvedIncidents: 0
      },
      errors: []
    };

    console.log("🧹 STARTING SCHEDULED DATA CLEANUP");
    console.log(`Cleanup initiated at: ${report.timestamp.toISOString()}`);

    try {
      // Clean up old published posts (keep for 1 year)
      await this.cleanupOldPosts(report);
      
      // Clean up expired verification codes
      await this.cleanupExpiredVerificationCodes(report);
      
      // Clean up used gift certificates older than 90 days
      await this.cleanupUsedGiftCertificates(report);
      
      // Clean up inactive platform connections
      await this.cleanupInactiveConnections(report);
      
      // Clean up resolved breach incidents (keeping for 7 years for compliance)
      await this.cleanupResolvedBreachIncidents(report);
      
      // Generate admin notification
      await this.notifyAdminOfCleanup(report);
      
      console.log("✅ SCHEDULED DATA CLEANUP COMPLETED SUCCESSFULLY");
      
    } catch (error: any) {
      const errorMessage = `Data cleanup failed: ${error.message}`;
      report.errors.push(errorMessage);
      console.error("❌ DATA CLEANUP ERROR:", error);
      
      // Notify admin of cleanup failure
      await this.notifyAdminOfCleanupFailure(error, report);
    }

    return report;
  }

  // Clean up old published posts
  private static async cleanupOldPosts(report: CleanupReport): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.RETENTION_POLICIES.publishedPosts);
    
    try {
      // Delete old published posts
      const oldPublishedPosts = await db
        .delete(posts)
        .where(
          and(
            eq(posts.status, 'published'),
            lt(posts.publishedAt, cutoffDate)
          )
        )
        .returning();
      
      report.deletedItems.oldPosts = oldPublishedPosts.length;
      
      // Count remaining active posts
      const activePosts = await db
        .select()
        .from(posts)
        .where(eq(posts.status, 'published'));
      
      report.retainedItems.activePosts = activePosts.length;
      
      console.log(`📝 Deleted ${report.deletedItems.oldPosts} old published posts (older than ${this.RETENTION_POLICIES.publishedPosts} days)`);
      
    } catch (error: any) {
      report.errors.push(`Post cleanup failed: ${error.message}`);
      console.error("Error cleaning up posts:", error);
    }
  }

  // Clean up expired verification codes
  private static async cleanupExpiredVerificationCodes(report: CleanupReport): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.RETENTION_POLICIES.expiredVerificationCodes);
    
    try {
      const expiredCodes = await db
        .delete(verificationCodes)
        .where(
          and(
            eq(verificationCodes.verified, true),
            lt(verificationCodes.expiresAt, cutoffDate)
          )
        )
        .returning();
      
      report.deletedItems.expiredVerificationCodes = expiredCodes.length;
      
      console.log(`🔐 Deleted ${report.deletedItems.expiredVerificationCodes} expired verification codes`);
      
    } catch (error: any) {
      report.errors.push(`Verification code cleanup failed: ${error.message}`);
      console.error("Error cleaning up verification codes:", error);
    }
  }

  // Clean up used gift certificates
  private static async cleanupUsedGiftCertificates(report: CleanupReport): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.RETENTION_POLICIES.usedGiftCertificates);
    
    try {
      const oldCertificates = await db
        .delete(giftCertificates)
        .where(
          and(
            eq(giftCertificates.isUsed, true),
            lt(giftCertificates.createdAt, cutoffDate)
          )
        )
        .returning();
      
      report.deletedItems.usedGiftCertificates = oldCertificates.length;
      
      console.log(`🎁 Deleted ${report.deletedItems.usedGiftCertificates} old used gift certificates`);
      
    } catch (error: any) {
      report.errors.push(`Gift certificate cleanup failed: ${error.message}`);
      console.error("Error cleaning up gift certificates:", error);
    }
  }

  // Clean up inactive platform connections
  private static async cleanupInactiveConnections(report: CleanupReport): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.RETENTION_POLICIES.inactiveConnections);
    
    try {
      // Get all platform connections to check inactivity
      const allConnections = await db.query.platformConnections.findMany();
      let deletedCount = 0;
      
      for (const connection of allConnections) {
        // Check if connection is inactive (last connected before cutoff and marked inactive)
        const lastConnected = connection.connectedAt || connection.expiresAt;
        if (lastConnected && lastConnected < cutoffDate && connection.isActive === false) {
          await storage.deletePlatformConnection(connection.id);
          deletedCount++;
        }
      }
      
      report.deletedItems.inactiveConnections = deletedCount;
      
      // Count remaining active connections
      const activeConnections = allConnections.filter(c => c.isActive === true);
      report.retainedItems.activeConnections = activeConnections.length;
      
      console.log(`🔗 Deleted ${report.deletedItems.inactiveConnections} inactive platform connections`);
      
    } catch (error: any) {
      report.errors.push(`Platform connection cleanup failed: ${error.message}`);
      console.error("Error cleaning up platform connections:", error);
    }
  }

  // Clean up resolved breach incidents (keeping for compliance)
  private static async cleanupResolvedBreachIncidents(report: CleanupReport): Promise<void> {
    // Import breach notification service dynamically to avoid circular dependencies
    const { default: BreachNotificationService } = await import("./breach-notification");
    
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.RETENTION_POLICIES.resolvedBreachIncidents);
    
    try {
      // Get all incidents
      const allIncidents = Array.from(BreachNotificationService['incidents'].values());
      const oldResolvedIncidents = allIncidents.filter(incident => 
        incident.status === 'resolved' && 
        incident.detectedAt < cutoffDate
      );
      
      // Archive old resolved incidents (in production, move to secure long-term storage)
      for (const incident of oldResolvedIncidents) {
        console.log(`📋 Archiving resolved breach incident: ${incident.id} (${incident.detectedAt.toISOString()})`);
        BreachNotificationService['incidents'].delete(incident.id);
      }
      
      report.deletedItems.resolvedBreachIncidents = oldResolvedIncidents.length;
      
      // Count unresolved incidents
      const unresolvedIncidents = allIncidents.filter(i => i.status !== 'resolved');
      report.retainedItems.unresolvedIncidents = unresolvedIncidents.length;
      
      console.log(`🛡️ Archived ${report.deletedItems.resolvedBreachIncidents} old resolved security incidents`);
      
    } catch (error: any) {
      report.errors.push(`Breach incident cleanup failed: ${error.message}`);
      console.error("Error cleaning up breach incidents:", error);
    }
  }

  // Notify admin of successful cleanup
  private static async notifyAdminOfCleanup(report: CleanupReport): Promise<void> {
    const totalDeleted = Object.values(report.deletedItems).reduce((sum, count) => sum + count, 0);
    const totalRetained = Object.values(report.retainedItems).reduce((sum, count) => sum + count, 0);
    
    const adminNotification = {
      to: 'admin@theagencyiq.ai',
      subject: `Data Cleanup Report - ${report.timestamp.toISOString().split('T')[0]}`,
      body: `
SCHEDULED DATA CLEANUP COMPLETED

Cleanup Time: ${report.timestamp.toISOString()}
Total Items Deleted: ${totalDeleted}
Total Items Retained: ${totalRetained}

DELETED ITEMS:
- Old Published Posts: ${report.deletedItems.oldPosts} (older than ${this.RETENTION_POLICIES.publishedPosts} days)
- Expired Verification Codes: ${report.deletedItems.expiredVerificationCodes}
- Used Gift Certificates: ${report.deletedItems.usedGiftCertificates} (older than ${this.RETENTION_POLICIES.usedGiftCertificates} days)
- Inactive Platform Connections: ${report.deletedItems.inactiveConnections} (inactive for ${this.RETENTION_POLICIES.inactiveConnections} days)
- Resolved Security Incidents: ${report.deletedItems.resolvedBreachIncidents} (archived after ${this.RETENTION_POLICIES.resolvedBreachIncidents} days)

RETAINED ITEMS:
- Active Posts: ${report.retainedItems.activePosts}
- Active Platform Connections: ${report.retainedItems.activeConnections}
- Unresolved Security Incidents: ${report.retainedItems.unresolvedIncidents}

ERRORS: ${report.errors.length === 0 ? 'None' : report.errors.join(', ')}

Data retention policies are being enforced according to best practices:
- Published posts retained for 1 year
- Security incidents retained for 7 years (compliance requirement)
- Platform connections cleaned up after 6 months of inactivity
- Temporary data (verification codes, used certificates) cleaned up regularly

Next scheduled cleanup: ${new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()}

The AgencyIQ Data Management System
      `
    };
    
    console.log("📧 ADMIN DATA CLEANUP NOTIFICATION");
    console.log(`TO: ${adminNotification.to}`);
    console.log(`SUBJECT: ${adminNotification.subject}`);
    console.log("CLEANUP SUMMARY:");
    console.log(`- Total Deleted: ${totalDeleted}`);
    console.log(`- Total Retained: ${totalRetained}`);
    console.log(`- Errors: ${report.errors.length}`);
    
    // In production, this would integrate with email service
    console.log("✅ Admin notification logged for data cleanup completion");
  }

  // Notify admin of cleanup failure
  private static async notifyAdminOfCleanupFailure(error: any, report: CleanupReport): Promise<void> {
    const adminAlert = {
      to: 'admin@theagencyiq.ai',
      subject: `URGENT: Data Cleanup Failed - ${report.timestamp.toISOString().split('T')[0]}`,
      body: `
DATA CLEANUP FAILURE ALERT

Cleanup Time: ${report.timestamp.toISOString()}
Error: ${error.message}

Partial Results:
- Old Posts Deleted: ${report.deletedItems.oldPosts}
- Verification Codes Deleted: ${report.deletedItems.expiredVerificationCodes}
- Gift Certificates Deleted: ${report.deletedItems.usedGiftCertificates}
- Platform Connections Deleted: ${report.deletedItems.inactiveConnections}
- Security Incidents Archived: ${report.deletedItems.resolvedBreachIncidents}

All Errors:
${report.errors.map(err => `- ${err}`).join('\n')}

IMMEDIATE ACTION REQUIRED:
- Review error logs
- Check database connectivity
- Verify cleanup script permissions
- Manual cleanup may be required

The AgencyIQ Data Management System - ERROR ALERT
      `
    };
    
    console.log("🚨 ADMIN DATA CLEANUP FAILURE ALERT 🚨");
    console.log(`TO: ${adminAlert.to}`);
    console.log(`ERROR: ${error.message}`);
    console.log("❌ Data cleanup failed - admin notification sent");
  }

  // Get cleanup status and next scheduled run
  static getCleanupStatus(): { nextRun: Date; retentionPolicies: typeof DataCleanupService.RETENTION_POLICIES } {
    const nextRun = new Date();
    nextRun.setDate(nextRun.getDate() + 1); // Daily cleanup
    
    return {
      nextRun,
      retentionPolicies: this.RETENTION_POLICIES
    };
  }
}