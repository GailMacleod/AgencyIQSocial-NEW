import { Request, Response } from 'express';
import RollbackSystem from '../scripts/rollback-system.js';

/**
 * API endpoints for rollback functionality
 */
export class RollbackAPI {
  private rollbackSystem: RollbackSystem;

  constructor() {
    this.rollbackSystem = new RollbackSystem();
  }

  /**
   * Create a new snapshot
   */
  async createSnapshot(req: Request, res: Response) {
    try {
      const { description } = req.body;
      const snapshotId = await this.rollbackSystem.createSnapshot(
        description || 'API created snapshot'
      );
      
      res.json({
        success: true,
        snapshotId,
        message: 'Snapshot created successfully'
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * List all snapshots
   */
  async listSnapshots(req: Request, res: Response) {
    try {
      const snapshots = this.rollbackSystem.listSnapshots();
      
      res.json({
        success: true,
        snapshots,
        total: snapshots.length
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * Rollback to a specific snapshot
   */
  async rollbackToSnapshot(req: Request, res: Response) {
    try {
      const { snapshotId } = req.params;
      
      if (!snapshotId) {
        return res.status(400).json({
          success: false,
          error: 'Snapshot ID is required'
        });
      }
      
      const result = await this.rollbackSystem.rollbackToSnapshot(snapshotId);
      
      res.json({
        success: true,
        result,
        message: 'Rollback completed successfully'
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * Delete a specific snapshot
   */
  async deleteSnapshot(req: Request, res: Response) {
    try {
      const { snapshotId } = req.params;
      
      if (!snapshotId) {
        return res.status(400).json({
          success: false,
          error: 'Snapshot ID is required'
        });
      }
      
      this.rollbackSystem.deleteSnapshot(snapshotId);
      
      res.json({
        success: true,
        message: 'Snapshot deleted successfully'
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }

  /**
   * Get system status and rollback capabilities
   */
  async getStatus(req: Request, res: Response) {
    try {
      const snapshots = this.rollbackSystem.listSnapshots();
      const latestSnapshot = snapshots[0];
      
      res.json({
        success: true,
        status: {
          available: true,
          totalSnapshots: snapshots.length,
          latestSnapshot: latestSnapshot ? {
            id: latestSnapshot.id,
            timestamp: latestSnapshot.timestamp,
            description: latestSnapshot.description
          } : null,
          maxSnapshots: 10
        }
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  }
}

export default RollbackAPI;