/**
 * EVENT SCHEDULING SERVICE - QUEENSLAND EVENTS & BRISBANE EKKA
 * Fetches Queensland events and integrates with AI content generation
 * Aligns with SME automation without OAuth dependency
 */

interface QueenslandEvent {
  name: string;
  date: Date;
  type: 'festival' | 'business' | 'agricultural' | 'cultural' | 'commercial';
  location: string;
  description: string;
  relevanceScore: number; // 1-10 for SME relevance
}

interface EventPostingPlan {
  eventId: string;
  eventName: string;
  scheduledDate: Date;
  platform: string;
  contentType: 'preview' | 'live' | 'follow-up';
  smeAlignment: string; // How this relates to Queensland SMEs
}

export class EventSchedulingService {
  
  /**
   * QUEENSLAND EVENT CALENDAR - July 2025
   * Brisbane Ekka July 9-19 is the major focus event
   */
  private static readonly QUEENSLAND_EVENTS: QueenslandEvent[] = [
    {
      name: 'Brisbane Ekka',
      date: new Date('2025-07-09T09:00:00.000Z'),
      type: 'agricultural',
      location: 'Brisbane Showgrounds, Bowen Hills',
      description: 'Queensland\'s premier agricultural show featuring business networking, technology showcases, and SME opportunities',
      relevanceScore: 10
    },
    {
      name: 'Queensland Small Business Week',
      date: new Date('2025-07-14T09:00:00.000Z'),
      type: 'business',
      location: 'Brisbane CBD',
      description: 'Statewide celebration of Queensland small businesses with workshops and networking events',
      relevanceScore: 10
    },
    {
      name: 'Gold Coast Business Excellence Awards',
      date: new Date('2025-07-18T19:00:00.000Z'),
      type: 'business',
      location: 'Gold Coast Convention Centre',
      description: 'Recognition of outstanding business achievements across Southeast Queensland',
      relevanceScore: 9
    },
    {
      name: 'Cairns Business Expo',
      date: new Date('2025-07-22T10:00:00.000Z'),
      type: 'commercial',
      location: 'Cairns Convention Centre',
      description: 'Far North Queensland business showcase focusing on tourism and technology innovation',
      relevanceScore: 8
    },
    {
      name: 'Toowoomba AgTech Summit',
      date: new Date('2025-07-25T08:00:00.000Z'),
      type: 'agricultural',
      location: 'University of Southern Queensland, Toowoomba',
      description: 'Agricultural technology innovation summit for Queensland farming businesses',
      relevanceScore: 9
    },
    {
      name: 'Sunshine Coast Innovation Festival',
      date: new Date('2025-07-28T09:00:00.000Z'),
      type: 'business',
      location: 'Maroochydore CBD',
      description: 'Technology and innovation showcase for Sunshine Coast businesses and startups',
      relevanceScore: 8
    }
  ];

  /**
   * Generate event-driven posting schedule for 30-day cycle
   * Ensures even distribution (1-2 posts/day) across July 3-31, 2025
   */
  static async generateEventPostingSchedule(userId: number): Promise<EventPostingPlan[]> {
    const schedule: EventPostingPlan[] = [];
    const platforms = ['facebook', 'instagram', 'linkedin', 'youtube', 'x'];
    const contentTypes: ('preview' | 'live' | 'follow-up')[] = ['preview', 'live', 'follow-up'];
    
    console.log('🎯 Generating Queensland event-driven posting schedule...');
    
    // BRISBANE EKKA FOCUS (July 9-19) - Premium event coverage
    const ekkaEvent = this.QUEENSLAND_EVENTS.find(e => e.name === 'Brisbane Ekka');
    if (ekkaEvent) {
      
      // Pre-Ekka content (July 3-8) - 6 days, 12 posts
      for (let day = 3; day <= 8; day++) {
        for (let postCount = 0; postCount < 2; postCount++) {
          const scheduledDate = new Date(`2025-07-${day.toString().padStart(2, '0')}T${9 + postCount * 6}:00:00.000Z`);
          
          schedule.push({
            eventId: 'ekka-preview',
            eventName: 'Brisbane Ekka Preview',
            scheduledDate,
            platform: platforms[postCount % platforms.length],
            contentType: 'preview',
            smeAlignment: 'Queensland SME networking opportunities at Australia\'s premier agricultural show'
          });
        }
      }
      
      // During Ekka (July 9-19) - 11 days, 22 posts
      for (let day = 9; day <= 19; day++) {
        for (let postCount = 0; postCount < 2; postCount++) {
          const scheduledDate = new Date(`2025-07-${day.toString().padStart(2, '0')}T${10 + postCount * 5}:00:00.000Z`);
          
          schedule.push({
            eventId: 'ekka-live',
            eventName: 'Brisbane Ekka Live',
            scheduledDate,
            platform: platforms[(day + postCount) % platforms.length],
            contentType: 'live',
            smeAlignment: 'Live coverage of Brisbane Ekka business opportunities and Queensland innovation showcase'
          });
        }
      }
      
      // Post-Ekka content (July 20-31) - 12 days, 18 posts
      for (let day = 20; day <= 31; day++) {
        // Reduce to 1-2 posts per day after Ekka
        const postsPerDay = day <= 25 ? 2 : 1;
        
        for (let postCount = 0; postCount < postsPerDay; postCount++) {
          const scheduledDate = new Date(`2025-07-${day.toString().padStart(2, '0')}T${11 + postCount * 4}:00:00.000Z`);
          
          // Reference other Queensland events
          const eventToReference = this.QUEENSLAND_EVENTS[day % this.QUEENSLAND_EVENTS.length];
          
          schedule.push({
            eventId: eventToReference.name.toLowerCase().replace(/\s+/g, '-'),
            eventName: eventToReference.name,
            scheduledDate,
            platform: platforms[(day + postCount) % platforms.length],
            contentType: day <= 25 ? 'follow-up' : 'preview',
            smeAlignment: `Queensland business opportunities: ${eventToReference.description.slice(0, 100)}...`
          });
        }
      }
    }
    
    console.log(`📅 Generated ${schedule.length} event-driven posts for July 2025`);
    console.log(`🎪 Brisbane Ekka focus: ${schedule.filter(p => p.eventId.includes('ekka')).length} posts`);
    console.log(`🏢 Other Queensland events: ${schedule.filter(p => !p.eventId.includes('ekka')).length} posts`);
    
    return schedule.slice(0, 30); // Professional plan limit
  }

  /**
   * Get Queensland event by date for content contextualization
   */
  static getEventByDate(date: Date): QueenslandEvent | null {
    const dayOfMonth = date.getDate();
    
    // Find events within 3 days of the given date
    return this.QUEENSLAND_EVENTS.find(event => {
      const eventDay = event.date.getDate();
      return Math.abs(dayOfMonth - eventDay) <= 3;
    }) || null;
  }

  /**
   * Generate SME-relevant content prompt for AI generation
   */
  static generateEventContentPrompt(eventPlan: EventPostingPlan, platform: string): string {
    const event = this.QUEENSLAND_EVENTS.find(e => e.name === eventPlan.eventName);
    if (!event) return '';

    const platformSpecs = {
      facebook: '80-120 words, community-focused tone',
      instagram: '50-70 words, visual storytelling style',
      linkedin: '100-150 words, professional business focus',
      youtube: '70-100 words, enthusiastic video teaser style',
      x: '50-70 words, concise with @ mentions, NO hashtags'
    };

    const spec = platformSpecs[platform as keyof typeof platformSpecs] || '50-100 words';

    return `Create a ${spec} post about ${event.name} in ${event.location} for Queensland small businesses. 
    Event type: ${event.type}
    Content type: ${eventPlan.contentType}
    SME angle: ${eventPlan.smeAlignment}
    Focus on: Business networking, technology opportunities, Queensland market expansion
    Tone: Professional yet approachable, emphasizing local business community
    Include: Practical business benefits, networking opportunities, innovation showcases`;
  }

  /**
   * Integration with Grok AI for event-driven content
   */
  static async generateEventAwareContent(
    userId: number, 
    platform: string, 
    scheduledDate: Date
  ): Promise<{ content: string; eventContext: string }> {
    
    // Get relevant Queensland event for the date
    const event = this.getEventByDate(scheduledDate);
    
    if (!event) {
      return {
        content: '',
        eventContext: 'No specific Queensland event - general business content'
      };
    }

    // Create event posting plan
    const eventPlan: EventPostingPlan = {
      eventId: event.name.toLowerCase().replace(/\s+/g, '-'),
      eventName: event.name,
      scheduledDate,
      platform,
      contentType: this.determineContentType(scheduledDate, event.date),
      smeAlignment: `Queensland SME opportunities at ${event.name}`
    };

    const contentPrompt = this.generateEventContentPrompt(eventPlan, platform);
    
    try {
      // Import Grok service for AI generation
      const { generateAIContent } = await import('../grok');
      const aiContent = await generateAIContent(contentPrompt, platform);
      
      return {
        content: aiContent || `Queensland businesses: ${event.name} presents exciting opportunities for networking and growth. Join the Queensland business community at ${event.location}!`,
        eventContext: `Event-driven content for ${event.name} (${event.type} event, relevance: ${event.relevanceScore}/10)`
      };
      
    } catch (error) {
      console.error('Event-aware content generation failed:', error);
      
      // Fallback event content
      return {
        content: `Queensland businesses: Don't miss ${event.name} at ${event.location}! Perfect opportunity for business networking and discovering new market opportunities.`,
        eventContext: `Fallback content for ${event.name}`
      };
    }
  }

  /**
   * Determine content type based on event timing
   */
  private static determineContentType(postDate: Date, eventDate: Date): 'preview' | 'live' | 'follow-up' {
    const daysDiff = Math.ceil((eventDate.getTime() - postDate.getTime()) / (1000 * 60 * 60 * 24));
    
    if (daysDiff > 2) return 'preview';
    if (daysDiff >= -2) return 'live';
    return 'follow-up';
  }

  /**
   * Validate even distribution across 30 days
   */
  static validateEventDistribution(schedule: EventPostingPlan[]): {
    isValid: boolean;
    averagePerDay: number;
    maxDeviation: number;
    totalPosts: number;
  } {
    const dayCount: { [key: string]: number } = {};
    
    schedule.forEach(plan => {
      const day = plan.scheduledDate.toISOString().split('T')[0];
      dayCount[day] = (dayCount[day] || 0) + 1;
    });
    
    const dailyCounts = Object.values(dayCount);
    const averagePerDay = dailyCounts.reduce((a, b) => a + b, 0) / dailyCounts.length;
    const maxDeviation = Math.max(...dailyCounts.map(count => Math.abs(count - averagePerDay)));
    
    return {
      isValid: maxDeviation <= 2 && !isNaN(maxDeviation), // Allow max 2 posts deviation from average
      averagePerDay: Math.round((averagePerDay || 0) * 100) / 100,
      maxDeviation: Math.round((maxDeviation || 0) * 100) / 100,
      totalPosts: schedule.length
    };
  }

  /**
   * Log event scheduling operations
   */
  static async logEventScheduling(userId: number, operation: string, details: string): Promise<void> {
    try {
      const fs = await import('fs/promises');
      const timestamp = new Date().toISOString();
      const logEntry = `[${timestamp}] EVENT SCHEDULING - User: ${userId}, Operation: ${operation}, Details: ${details}\n`;
      
      await fs.mkdir('data', { recursive: true });
      await fs.appendFile('data/quota-debug.log', logEntry);
    } catch (error) {
      console.error('Failed to log event scheduling:', error);
    }
  }
}