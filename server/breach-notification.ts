import { storage } from './storage';

interface BreachIncident {
  id: string;
  userId: number;
  incidentType: 'data_access' | 'account_compromise' | 'platform_breach' | 'system_vulnerability';
  description: string;
  affectedPlatforms: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectedAt: Date;
  reportedAt?: Date;
  notificationSent: boolean;
  documentationPath?: string;
  status: 'detected' | 'investigating' | 'reported' | 'resolved';
}

export class BreachNotificationService {
  private static incidents: Map<string, BreachIncident> = new Map();
  
  // Record a security incident
  static async recordIncident(
    userId: number,
    incidentType: BreachIncident['incidentType'],
    description: string,
    affectedPlatforms: string[] = [],
    severity: BreachIncident['severity'] = 'medium'
  ): Promise<string> {
    const incidentId = `BREACH_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const incident: BreachIncident = {
      id: incidentId,
      userId,
      incidentType,
      description,
      affectedPlatforms,
      severity,
      detectedAt: new Date(),
      notificationSent: false,
      status: 'detected'
    };
    
    this.incidents.set(incidentId, incident);
    
    console.log(`SECURITY BREACH DETECTED: ${incidentId} for user ${userId}`);
    console.log(`Type: ${incidentType}, Severity: ${severity}`);
    console.log(`Description: ${description}`);
    console.log(`Affected platforms: ${affectedPlatforms.join(', ')}`);
    
    // Start 72-hour notification timer
    this.schedule72HourNotification(incidentId);
    
    return incidentId;
  }
  
  // Schedule 72-hour breach notification
  private static schedule72HourNotification(incidentId: string): void {
    const SEVENTY_TWO_HOURS = 72 * 60 * 60 * 1000; // 72 hours in milliseconds
    
    setTimeout(async () => {
      const incident = this.incidents.get(incidentId);
      if (!incident) return;
      
      if (!incident.notificationSent && incident.status !== 'resolved') {
        await this.sendBreachNotification(incidentId);
      }
    }, SEVENTY_TWO_HOURS);
    
    console.log(`72-hour breach notification scheduled for incident: ${incidentId}`);
  }
  
  // Send breach notification with documentation
  static async sendBreachNotification(incidentId: string): Promise<void> {
    const incident = this.incidents.get(incidentId);
    if (!incident) {
      console.error(`Incident ${incidentId} not found for notification`);
      return;
    }
    
    try {
      const user = await storage.getUser(incident.userId);
      if (!user) {
        console.error(`User ${incident.userId} not found for breach notification`);
        return;
      }
      
      // Generate documentation
      const documentation = await this.generateBreachDocumentation(incident);
      
      // Send immediate notification to administrator
      await this.notifyAdministrator(incident, user, documentation);
      
      // Log breach notification
      console.log(`===== BREACH NOTIFICATION SENT =====`);
      console.log(`Incident ID: ${incident.id}`);
      console.log(`User: ${user.email}`);
      console.log(`Detected: ${incident.detectedAt.toISOString()}`);
      console.log(`Notification sent: ${new Date().toISOString()}`);
      console.log(`Type: ${incident.incidentType}`);
      console.log(`Severity: ${incident.severity}`);
      console.log(`Description: ${incident.description}`);
      console.log(`Affected platforms: ${incident.affectedPlatforms.join(', ')}`);
      console.log(`Documentation: ${documentation}`);
      console.log(`======================================`);
      
      // Update incident status
      incident.notificationSent = true;
      incident.reportedAt = new Date();
      incident.status = 'reported';
      incident.documentationPath = `breach_docs/${incident.id}.json`;
      
      // Store documentation
      await this.storeBreachDocumentation(incident, documentation);
      
    } catch (error) {
      console.error(`Failed to send breach notification for ${incidentId}:`, error);
    }
  }
  
  // Notify administrator of security breach
  private static async notifyAdministrator(incident: BreachIncident, user: any, documentation: string): Promise<void> {
    const adminNotification = {
      to: 'admin@theagencyiq.ai', // Administrator email
      subject: `URGENT: Security Breach Detected - ${incident.severity.toUpperCase()} - ${incident.id}`,
      body: `
SECURITY BREACH ALERT

Incident Details:
- ID: ${incident.id}
- Type: ${incident.incidentType}
- Severity: ${incident.severity.toUpperCase()}
- Detected: ${incident.detectedAt.toISOString()}
- User Affected: ${user.email} (ID: ${incident.userId})

Description: ${incident.description}

Affected Platforms: ${incident.affectedPlatforms.join(', ')}

Time Since Detection: ${Math.round((Date.now() - incident.detectedAt.getTime()) / (1000 * 60 * 60))} hours

IMMEDIATE ACTIONS REQUIRED:
${this.getMitigationSteps(incident.incidentType).map(step => `- ${step}`).join('\n')}

Full documentation attached.

This is an automated security alert. Please investigate immediately.

The AgencyIQ Security System
      `,
      documentation: documentation
    };
    
    // Log notification for administrator
    console.log(`🚨 ADMIN SECURITY ALERT 🚨`);
    console.log(`TO: ${adminNotification.to}`);
    console.log(`SUBJECT: ${adminNotification.subject}`);
    console.log(`BREACH DETAILS:`);
    console.log(`- Incident: ${incident.id}`);
    console.log(`- User: ${user.email}`);
    console.log(`- Type: ${incident.incidentType}`);
    console.log(`- Severity: ${incident.severity}`);
    console.log(`- Platforms: ${incident.affectedPlatforms.join(', ')}`);
    console.log(`- Description: ${incident.description}`);
    console.log(`🚨 IMMEDIATE INVESTIGATION REQUIRED 🚨`);
    
    // In production, this would integrate with email service like SendGrid
    // For now, we ensure the alert is prominently logged
  }
  
  // Generate comprehensive breach documentation
  private static async generateBreachDocumentation(incident: BreachIncident): Promise<string> {
    const user = await storage.getUser(incident.userId);
    const connections = await storage.getPlatformConnectionsByUser(incident.userId);
    
    const documentation = {
      incidentDetails: {
        id: incident.id,
        type: incident.incidentType,
        severity: incident.severity,
        detectedAt: incident.detectedAt.toISOString(),
        reportedAt: new Date().toISOString(),
        description: incident.description,
        affectedPlatforms: incident.affectedPlatforms
      },
      userDetails: {
        userId: incident.userId,
        email: user?.email,
        subscriptionPlan: user?.subscriptionPlan,
        connectedPlatforms: connections.map(c => ({
          platform: c.platform,
          connectedAt: c.connectedAt,
          isActive: c.isActive
        }))
      },
      timeline: {
        detectionTime: incident.detectedAt.toISOString(),
        notificationTime: new Date().toISOString(),
        timeBetween: `${Math.round((Date.now() - incident.detectedAt.getTime()) / (1000 * 60 * 60))} hours`
      },
      mitigationSteps: this.getMitigationSteps(incident.incidentType),
      complianceRequirements: {
        gdprNotificationRequired: true,
        ccpaNotificationRequired: true,
        notificationPeriod: '72 hours from detection',
        documentationRetention: '7 years'
      }
    };
    
    return JSON.stringify(documentation, null, 2);
  }
  
  // Get appropriate mitigation steps based on incident type
  private static getMitigationSteps(incidentType: BreachIncident['incidentType']): string[] {
    const steps: Record<BreachIncident['incidentType'], string[]> = {
      data_access: [
        'Immediately revoke all platform access tokens',
        'Force password reset for affected users',
        'Audit access logs for unauthorized activity',
        'Notify affected platforms of potential compromise'
      ],
      account_compromise: [
        'Suspend user account immediately',
        'Invalidate all active sessions',
        'Require identity verification for account recovery',
        'Review recent account activity for suspicious behavior'
      ],
      platform_breach: [
        'Disconnect affected platform integrations',
        'Delete cached platform data',
        'Monitor for unusual API activity',
        'Coordinate with platform security teams'
      ],
      system_vulnerability: [
        'Apply security patches immediately',
        'Conduct full system security audit',
        'Review access controls and permissions',
        'Implement additional monitoring'
      ]
    };
    
    return steps[incidentType] || ['Conduct thorough security investigation'];
  }
  
  // Store breach documentation for compliance
  private static async storeBreachDocumentation(incident: BreachIncident, documentation: string): Promise<void> {
    try {
      // In production, this would store to secure, compliant storage
      console.log(`Storing breach documentation for incident ${incident.id}`);
      console.log(`Documentation path: ${incident.documentationPath}`);
      console.log(`Documentation size: ${documentation.length} characters`);
      
      // Log for audit trail
      console.log(`AUDIT LOG: Breach documentation stored for ${incident.id} at ${new Date().toISOString()}`);
      
    } catch (error) {
      console.error(`Failed to store breach documentation for ${incident.id}:`, error);
    }
  }
  
  // Get all incidents for a user
  static getIncidentsForUser(userId: number): BreachIncident[] {
    return Array.from(this.incidents.values()).filter(incident => incident.userId === userId);
  }
  
  // Get incident by ID
  static getIncident(incidentId: string): BreachIncident | undefined {
    return this.incidents.get(incidentId);
  }
  
  // Mark incident as resolved
  static async resolveIncident(incidentId: string): Promise<void> {
    const incident = this.incidents.get(incidentId);
    if (incident) {
      incident.status = 'resolved';
      console.log(`Incident ${incidentId} marked as resolved`);
    }
  }
  
  // Check for incidents requiring notification
  static checkPendingNotifications(): void {
    const now = Date.now();
    const SEVENTY_TWO_HOURS = 72 * 60 * 60 * 1000;
    
    this.incidents.forEach(async (incident, id) => {
      if (!incident.notificationSent && 
          incident.status !== 'resolved' && 
          (now - incident.detectedAt.getTime()) >= SEVENTY_TWO_HOURS) {
        await this.sendBreachNotification(id);
      }
    });
  }
}

export default BreachNotificationService;