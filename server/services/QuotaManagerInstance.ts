/**
 * QUOTA MANAGER SINGLETON INSTANCE
 * Provides global access to quota management system
 */

import QuotaManager from './QuotaManager';

// Create and export singleton instance
export const quotaManager = new QuotaManager();
export default quotaManager;