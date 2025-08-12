import {
  users,
  posts,
  platformConnections,
  brandPurpose,
  verificationCodes,
  giftCertificates,
  giftCertificateActionLog,
  subscriptionAnalytics,
  postLedger,
  postSchedule,
  type User,
  type InsertUser,
  type Post,
  type InsertPost,
  type PlatformConnection,
  type InsertPlatformConnection,
  type BrandPurpose,
  type InsertBrandPurpose,
  type VerificationCode,
  type InsertVerificationCode,
  type GiftCertificate,
  type InsertGiftCertificate,
  type GiftCertificateActionLog,
  type InsertGiftCertificateActionLog,
  type SubscriptionAnalytics,
  type InsertSubscriptionAnalytics,
} from "@shared/schema";
import { db } from "./db";
import { eq, and, desc, gte } from "drizzle-orm";
import { sql } from "drizzle-orm";

export interface IStorage {
  // User operations - phone UID architecture
  getUser(id: number): Promise<User | undefined>;
  getAllUsers(): Promise<User[]>;
  getUserByPhone(phone: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  getUserByStripeSubscriptionId(subscriptionId: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: number, updates: Partial<InsertUser>): Promise<User>;
  updateUserPhone(oldPhone: string, newPhone: string): Promise<User>;
  updateUserStripeInfo(id: number, stripeCustomerId: string, stripeSubscriptionId: string): Promise<User>;
  updateStripeCustomerId(userId: number, stripeCustomerId: string): Promise<User>;

  // Post operations
  getPostsByUser(userId: number): Promise<Post[]>;
  getPostsByUserPaginated(userId: number, limit: number, offset: number): Promise<Post[]>;
  createPost(post: InsertPost): Promise<Post>;
  updatePost(id: number, updates: Partial<InsertPost>): Promise<Post>;
  deletePost(id: number): Promise<void>;
  getPost(postId: number): Promise<Post | undefined>;

  // Platform connection operations
  getPlatformConnectionsByUser(userId: number): Promise<PlatformConnection[]>;
  getPlatformConnection(userId: number, platform: string): Promise<PlatformConnection | undefined>;
  getConnectedPlatforms(userId: number): Promise<{ [key: string]: boolean }>;
  createPlatformConnection(connection: InsertPlatformConnection): Promise<PlatformConnection>;
  updatePlatformConnection(id: number, updates: Partial<InsertPlatformConnection>): Promise<PlatformConnection>;
  updatePlatformConnectionByPlatform(userId: number, platform: string, updates: Partial<InsertPlatformConnection>): Promise<PlatformConnection>;
  deletePlatformConnection(id: number): Promise<void>;

  // Brand purpose operations
  getBrandPurposeByUser(userId: number): Promise<BrandPurpose | undefined>;
  createBrandPurpose(brandPurpose: InsertBrandPurpose): Promise<BrandPurpose>;
  updateBrandPurpose(id: number, updates: Partial<InsertBrandPurpose>): Promise<BrandPurpose>;

  // Verification code operations
  createVerificationCode(code: InsertVerificationCode): Promise<VerificationCode>;
  getVerificationCode(phone: string, code: string): Promise<VerificationCode | undefined>;
  markVerificationCodeUsed(id: number): Promise<void>;

  // Gift certificate operations with enhanced user tracking
  createGiftCertificate(certificate: InsertGiftCertificate, createdBy?: number): Promise<GiftCertificate>;
  getGiftCertificate(code: string): Promise<GiftCertificate | undefined>;
  redeemGiftCertificate(code: string, userId: number): Promise<GiftCertificate>;
  getAllGiftCertificates(): Promise<GiftCertificate[]>;
  getGiftCertificatesByCreator(createdBy: number): Promise<GiftCertificate[]>;
  getGiftCertificatesByRedeemer(redeemedBy: number): Promise<GiftCertificate[]>;

  // Gift certificate action logging
  logGiftCertificateAction(action: InsertGiftCertificateActionLog): Promise<GiftCertificateActionLog>;
  getGiftCertificateActionLog(certificateId: number): Promise<GiftCertificateActionLog[]>;
  getGiftCertificateActionLogByCode(certificateCode: string): Promise<GiftCertificateActionLog[]>;
  getGiftCertificateActionLogByUser(userId: number): Promise<GiftCertificateActionLog[]>;

  // Platform connection search operations
  getPlatformConnectionsByPlatformUserId(platformUserId: string): Promise<PlatformConnection[]>;

  // Post ledger operations for synchronization
  getPostLedgerByUser(userId: string): Promise<any | undefined>;
  createPostLedger(ledger: any): Promise<any>;
  updatePostLedger(userId: string, updates: any): Promise<any>;

  // OAuth token operations for TokenManager integration
  storeOAuthToken(userId: number, provider: string, tokenData: any): Promise<void>;
  getOAuthToken(userId: number, provider: string): Promise<any>;
  getUserOAuthTokens(userId: number): Promise<Record<string, any>>;
  removeOAuthToken(userId: number, provider: string): Promise<void>;
}

export class DatabaseStorage implements IStorage {
  // User operations - phone UID architecture
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getAllUsers(): Promise<User[]> {
    return await db.select().from(users);
  }

  async getUserByPhone(phone: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.phone, phone)); // FIXED: Use phone, not userId
    return user;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }

  async getUserByStripeSubscriptionId(subscriptionId: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.stripeSubscriptionId, subscriptionId));
    return user;
  }

  async createUser(user: InsertUser): Promise<User> {
    const [newUser] = await db.insert(users).values(user).returning();
    return newUser;
  }

  async updateUser(id: number, updates: Partial<InsertUser>): Promise<User> {
    const [updatedUser] = await db
      .update(users)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return updatedUser;
  }

  async updateUserPhone(oldPhone: string, newPhone: string): Promise<User> {
    return await db.transaction(async (tx) => {
      const [user] = await tx
        .update(users)
        .set({ phone: newPhone, updatedAt: new Date() })
        .where(eq(users.phone, oldPhone))
        .returning();
      if (!user) throw new Error(`User with phone ${oldPhone} not found`);

      // Use parameterized queries to avoid SQL injection
      await tx.execute(sql`
        UPDATE ${postLedger}
        SET userId = ${newPhone}
        WHERE userId = ${oldPhone}
      `);
      await tx.execute(sql`
        UPDATE ${postSchedule}
        SET userId = ${newPhone}
        WHERE userId = ${oldPhone}
      `);
      console.log(`Successfully migrated all data from ${oldPhone} to ${newPhone}`);
      return user;
    });
  }

  async updateUserStripeInfo(id: number, stripeCustomerId: string, stripeSubscriptionId: string): Promise<User> {
    const [updatedUser] = await db
      .update(users)
      .set({ stripeCustomerId, stripeSubscriptionId, updatedAt: new Date() })
      .where(eq(users.id, id))
      .returning();
    return updatedUser;
  }

  async updateStripeCustomerId(userId: number, stripeCustomerId: string): Promise<User> {
    const [updatedUser] = await db
      .update(users)
      .set({ stripeCustomerId, updatedAt: new Date() })
      .where(eq(users.id, userId))
      .returning();
    return updatedUser;
  }

  // Post operations
  async getPostsByUser(userId: number): Promise<Post[]> {
    return await db
      .select()
      .from(posts)
      .where(eq(posts.userId, userId))
      .orderBy(desc(posts.createdAt)); // FIXED: Use createdAt instead of scheduledFor
  }

  async getPostsByUserPaginated(userId: number, limit: number, offset: number): Promise<Post[]> {
    return await db
      .select()
      .from(posts)
      .where(eq(posts.userId, userId))
      .orderBy(desc(posts.createdAt))
      .limit(limit)
      .offset(offset);
  }

  async createPost(post: InsertPost): Promise<Post> {
    const [newPost] = await db.insert(posts).values(post).returning();
    return newPost;
  }

  async updatePost(id: number, updates: Partial<InsertPost>): Promise<Post> {
    const [updatedPost] = await db
      .update(posts)
      .set(updates)
      .where(eq(posts.id, id))
      .returning();
    return updatedPost;
  }

  async deletePost(id: number): Promise<void> {
    await db.delete(posts).where(eq(posts.id, id));
  }

  async getPost(postId: number): Promise<Post | undefined> {
    const [post] = await db.select().from(posts).where(eq(posts.id, postId));
    return post;
  }

  // Platform connection operations
  async getPlatformConnectionsByUser(userId: number): Promise<PlatformConnection[]> {
    return await db
      .select()
      .from(platformConnections)
      .where(eq(platformConnections.userId, userId));
  }

  async getPlatformConnection(userId: number, platform: string): Promise<PlatformConnection | undefined> {
    const [connection] = await db
      .select()
      .from(platformConnections)
      .where(and(eq(platformConnections.userId, userId), eq(platformConnections.platform, platform)));
    return connection;
  }

  async getConnectedPlatforms(userId: number): Promise<{ [key: string]: boolean }> {
    const connections = await db
      .select()
      .from(platformConnections)
      .where(eq(platformConnections.userId, userId));
    return connections.reduce((acc, conn) => ({ ...acc, [conn.platform]: conn.isActive || false }), {});
  }

  async createPlatformConnection(connection: InsertPlatformConnection): Promise<PlatformConnection> {
    const [newConnection] = await db.insert(platformConnections).values(connection).returning();
    return newConnection;
  }

  async updatePlatformConnection(id: number, updates: Partial<InsertPlatformConnection>): Promise<PlatformConnection> {
    const [updatedConnection] = await db
      .update(platformConnections)
      .set(updates)
      .where(eq(platformConnections.id, id))
      .returning();
    return updatedConnection;
  }

  async updatePlatformConnectionByPlatform(userId: number, platform: string, updates: Partial<InsertPlatformConnection>): Promise<PlatformConnection> {
    const [updatedConnection] = await db
      .update(platformConnections)
      .set(updates)
      .where(and(eq(platformConnections.userId, userId), eq(platformConnections.platform, platform)))
      .returning();
    return updatedConnection;
  }

  async deletePlatformConnection(id: number): Promise<void> {
    await db.delete(platformConnections).where(eq(platformConnections.id, id));
  }

  // Brand purpose operations
  async getBrandPurposeByUser(userId: number): Promise<BrandPurpose | undefined> {
    const [brandPurpose] = await db
      .select()
      .from(brandPurpose)
      .where(eq(brandPurpose.userId, userId));
    return brandPurpose;
  }

  async createBrandPurpose(brandPurpose: InsertBrandPurpose): Promise<BrandPurpose> {
    const [newBrandPurpose] = await db.insert(brandPurpose).values(brandPurpose).returning();
    return newBrandPurpose;
  }

  async updateBrandPurpose(id: number, updates: Partial<InsertBrandPurpose>): Promise<BrandPurpose> {
    const [updatedBrandPurpose] = await db
      .update(brandPurpose)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(brandPurpose.id, id))
      .returning();
    return updatedBrandPurpose;
  }

  // Verification code operations
  async createVerificationCode(code: InsertVerificationCode): Promise<VerificationCode> {
    const [newCode] = await db.insert(verificationCodes).values(code).returning();
    return newCode;
  }

  async getVerificationCode(phone: string, code: string): Promise<VerificationCode | undefined> {
    const [verificationCode] = await db
      .select()
      .from(verificationCodes)
      .where(and(eq(verificationCodes.phone, phone), eq(verificationCodes.code, code)))
      .orderBy(desc(verificationCodes.createdAt))
      .limit(1);
    return verificationCode;
  }

  async markVerificationCodeUsed(id: number): Promise<void> {
    await db
      .update(verificationCodes)
      .set({ used: true }) // FIXED: Use 'used' instead of 'verified' to match schema intent
      .where(eq(verificationCodes.id, id));
  }

  // Gift certificate operations with enhanced user tracking
  async createGiftCertificate(certificate: InsertGiftCertificate, createdBy?: number): Promise<GiftCertificate> {
    const certificateData = { ...certificate, createdBy };
    const [newCertificate] = await db.insert(giftCertificates).values(certificateData).returning();
    await this.logGiftCertificateAction({
      certificateId: newCertificate.id,
      certificateCode: newCertificate.code,
      actionType: 'created',
      actionBy: createdBy,
      actionDetails: { plan: newCertificate.plan, createdFor: newCertificate.createdFor },
      success: true,
    });
    return newCertificate;
  }

  async getGiftCertificate(code: string): Promise<GiftCertificate | undefined> {
    const [certificate] = await db
      .select()
      .from(giftCertificates)
      .where(eq(giftCertificates.code, code));
    return certificate;
  }

  async redeemGiftCertificate(code: string, userId: number): Promise<GiftCertificate> {
    const [updatedCertificate] = await db
      .update(giftCertificates)
      .set({ isUsed: true, redeemedBy: userId, redeemedAt: new Date() })
      .where(eq(giftCertificates.code, code))
      .returning();
    await this.logGiftCertificateAction({
      certificateId: updatedCertificate.id,
      certificateCode: updatedCertificate.code,
      actionType: 'redeemed',
      actionBy: userId,
      actionDetails: { plan: updatedCertificate.plan, originalCreatedFor: updatedCertificate.createdFor },
      success: true,
    });
    return updatedCertificate;
  }

  async getAllGiftCertificates(): Promise<GiftCertificate[]> {
    return await db
      .select()
      .from(giftCertificates)
      .orderBy(desc(giftCertificates.createdAt));
  }

  async getGiftCertificatesByCreator(createdBy: number): Promise<GiftCertificate[]> {
    return await db
      .select()
      .from(giftCertificates)
      .where(eq(giftCertificates.createdBy, createdBy))
      .orderBy(desc(giftCertificates.createdAt));
  }

  async getGiftCertificatesByRedeemer(redeemedBy: number): Promise<GiftCertificate[]> {
    return await db
      .select()
      .from(giftCertificates)
      .where(eq(giftCertificates.redeemedBy, redeemedBy))
      .orderBy(desc(giftCertificates.redeemedAt));
  }

  // Gift certificate action logging
  async logGiftCertificateAction(action: InsertGiftCertificateActionLog): Promise<GiftCertificateActionLog> {
    const [logEntry] = await db.insert(giftCertificateActionLog).values(action).returning();
    return logEntry;
  }

  async getGiftCertificateActionLog(certificateId: number): Promise<GiftCertificateActionLog[]> {
    return await db
      .select()
      .from(giftCertificateActionLog)
      .where(eq(giftCertificateActionLog.certificateId, certificateId))
      .orderBy(desc(giftCertificateActionLog.createdAt));
  }

  async getGiftCertificateActionLogByCode(certificateCode: string): Promise<GiftCertificateActionLog[]> {
    const certificate = await this.getGiftCertificate(certificateCode);
    if (!certificate) return [];
    return await this.getGiftCertificateActionLog(certificate.id);
  }

  async getGiftCertificateActionLogByUser(userId: number): Promise<GiftCertificateActionLog[]> {
    return await db
      .select()
      .from(giftCertificateActionLog)
      .where(eq(giftCertificateActionLog.actionBy, userId))
      .orderBy(desc(giftCertificateActionLog.createdAt));
  }

  // Platform connection search operations
  async getPlatformConnectionsByPlatformUserId(platformUserId: string): Promise<PlatformConnection[]> {
    return await db
      .select()
      .from(platformConnections)
      .where(eq(platformConnections.platformUserId, platformUserId));
  }

  // Post ledger operations for synchronization
  async getPostLedgerByUser(userId: string): Promise<any | undefined> {
    const [ledger] = await db.select().from(postLedger).where(eq(postLedger.userId, userId));
    return ledger;
  }

  async createPostLedger(ledger: any): Promise<any> {
    const [newLedger] = await db.insert(postLedger).values(ledger).returning();
    return newLedger;
  }

  async updatePostLedger(userId: string, updates: any): Promise<any> {
    const [updatedLedger] = await db
      .update(postLedger)
      .set(updates)
      .where(eq(postLedger.userId, userId))
      .returning();
    return updatedLedger;
  }

  // OAuth token operations for TokenManager integration
  async storeOAuthToken(userId: number, provider: string, tokenData: any): Promise<void> {
    const { oauthTokens } = await import('@shared/schema');
    await db.insert(oauthTokens)
      .values({
        userId: userId.toString(),
        provider,
        accessToken: tokenData.accessToken,
        refreshToken: tokenData.refreshToken,
        expiresAt: new Date(tokenData.expiresAt),
        scope: tokenData.scope || [],
        profileId: tokenData.profileId,
      })
      .onConflictDoUpdate({
        target: [oauthTokens.userId, oauthTokens.provider],
        set: {
          accessToken: tokenData.accessToken,
          refreshToken: tokenData.refreshToken,
          expiresAt: new Date(tokenData.expiresAt),
          scope: tokenData.scope || [],
        },
      });
  }

  async getOAuthToken(userId: number, provider: string): Promise<any> {
    const { oauthTokens } = await import('@shared/schema');
    const [token] = await db.select()
      .from(oauthTokens)
      .where(and(eq(oauthTokens.userId, userId.toString()), eq(oauthTokens.provider, provider)));
    return token || null;
  }

  async getUserOAuthTokens(userId: number): Promise<Record<string, any>> {
    const { oauthTokens } = await import('@shared/schema');
    const tokens = await db.select()
      .from(oauthTokens)
      .where(eq(oauthTokens.userId, userId.toString()));
    return tokens.reduce((acc, token) => ({
      ...acc,
      [token.provider]: {
        accessToken: token.accessToken,
        refreshToken: token.refreshToken,
        expiresAt: token.expiresAt?.getTime(),
        scope: token.scope || [],
        provider: token.provider,
      },
    }), {});
  }

  async removeOAuthToken(userId: number, provider: string): Promise<void> {
    const { oauthTokens } = await import('@shared/schema');
    await db.delete(oauthTokens)
      .where(and(eq(oauthTokens.userId, userId.toString()), eq(oauthTokens.provider, provider)));
  }
}

export const storage = new DatabaseStorage();