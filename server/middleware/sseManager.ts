import type { Response } from 'express';

interface SSEClient {
  id: string;
  userId: string;
  response: Response;
  lastPing: number;
}

export class SSEManager {
  private static instance: SSEManager;
  private clients: Map<string, SSEClient> = new Map();
  private pingInterval: NodeJS.Timeout;

  private constructor() {
    // Ping clients every 30 seconds to keep connections alive
    this.pingInterval = setInterval(() => {
      this.pingAllClients();
    }, 30000);
  }

  static getInstance(): SSEManager {
    if (!SSEManager.instance) {
      SSEManager.instance = new SSEManager();
    }
    return SSEManager.instance;
  }

  addClient(clientId: string, userId: string, response: Response): void {
    const client: SSEClient = {
      id: clientId,
      userId,
      response,
      lastPing: Date.now()
    };

    this.clients.set(clientId, client);
    console.log(`✅ [SSE] Client connected: ${clientId} for user ${userId}`);

    // Send initial connection confirmation
    this.sendToClient(clientId, { type: 'connected', timestamp: new Date().toISOString() });

    // Handle client disconnect
    response.on('close', () => {
      this.removeClient(clientId);
    });
  }

  removeClient(clientId: string): void {
    const client = this.clients.get(clientId);
    if (client) {
      this.clients.delete(clientId);
      console.log(`🔌 [SSE] Client disconnected: ${clientId}`);
    }
  }

  sendToClient(clientId: string, data: any): boolean {
    const client = this.clients.get(clientId);
    if (!client) return false;

    try {
      client.response.write(`data: ${JSON.stringify(data)}\n\n`);
      client.lastPing = Date.now();
      return true;
    } catch (error) {
      console.error(`❌ [SSE] Failed to send to client ${clientId}:`, error);
      this.removeClient(clientId);
      return false;
    }
  }

  sendToUser(userId: string, data: any): number {
    let sentCount = 0;
    this.clients.forEach((client, clientId) => {
      if (client.userId === userId) {
        if (this.sendToClient(clientId, data)) {
          sentCount++;
        }
      }
    });
    return sentCount;
  }

  broadcastToAll(data: any): number {
    let sentCount = 0;
    this.clients.forEach((client, clientId) => {
      if (this.sendToClient(clientId, data)) {
        sentCount++;
      }
    });
    return sentCount;
  }

  private pingAllClients(): void {
    const now = Date.now();
    const staleThreshold = 90000; // 90 seconds

    this.clients.forEach((client, clientId) => {
      // Remove stale clients
      if (now - client.lastPing > staleThreshold) {
        console.log(`🧹 [SSE] Removing stale client: ${clientId}`);
        this.removeClient(clientId);
        return;
      }

      // Send ping
      this.sendToClient(clientId, { type: 'ping', timestamp: new Date().toISOString() });
    });
  }

  getClientCount(): number {
    return this.clients.size;
  }

  getUserClients(userId: string): number {
    return Array.from(this.clients.values()).filter(client => client.userId === userId).length;
  }

  shutdown(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
    }
    
    // Close all client connections
    this.clients.forEach((client, clientId) => {
      try {
        client.response.end();
      } catch (error) {
        console.error(`Error closing client ${clientId}:`, error);
      }
    });
    
    this.clients.clear();
    console.log('🛑 [SSE] SSE Manager shutdown complete');
  }
}

export default SSEManager;