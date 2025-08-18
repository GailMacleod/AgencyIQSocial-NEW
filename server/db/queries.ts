import { db } from '../db';
import { posts } from '@shared/schema';
import { eq, and, sql } from 'drizzle-orm';

/**
 * Get published post count for a user
 */
export async function getPublishedPostCount(userId: number): Promise<number> {
  try {
    const result = await db
      .select({ count: sql<number>`COUNT(*)` })
      .from(posts)
      .where(
        and(
          eq(posts.userId, userId),
          eq(posts.status, 'published')
        )
      );

    return result[0]?.count || 0;
  } catch (error) {
    console.error('Error getting published post count:', error);
    return 0;
  }
}

/**
 * Test published post count with sample data
 */
export async function testPublishedPostCount(): Promise<void> {
  try {
    console.log('Testing published post count query...');
    
    // Test with sample user IDs
    const testUserIds = [1, 2, 3];
    
    for (const userId of testUserIds) {
      const count = await getPublishedPostCount(userId);
      console.log(`User ${userId}: ${count} published posts`);
    }
    
    console.log('Published post count test completed');
  } catch (error) {
    console.error('Error testing published post count:', error);
  }
}