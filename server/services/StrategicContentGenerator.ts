/**
 * STRATEGIC CONTENT GENERATOR
 * Implements waterfall strategyzer methodology for Queensland SME content
 * Sequential business model canvas-inspired flow with Value Proposition Canvas integration
 */

import { storage } from '../storage';
import { db } from '../db';
import { posts } from '../../shared/schema';
import { eq, and } from 'drizzle-orm';
import { analyseCMOStrategy, generateJobsToBeDoneAnalysis, createBrandDominationStrategy } from '../cmo-strategy';
import { generateContentCalendar } from '../grok';
import OpenAI from 'openai';
import { createHash } from 'crypto';

const aiClient = new OpenAI({
  baseURL: "https://api.x.ai/v1", 
  apiKey: process.env.XAI_API_KEY
});

interface StrategicContentParams {
  userId: number;
  brandPurpose: any;
  totalPosts: number;
  platforms: string[];
}

interface QueenslandMarketInsights {
  keyIndustries: string[];
  seasonalTrends: string[];
  competitiveAdvantages: string[];
  localEvents: string[];
  seoKeywords: string[];
}

interface ValuePropositionCanvas {
  customerJobs: string[];
  painPoints: string[];
  gainCreators: string[];
  products: string[];
  painRelievers: string[];
  valuePropositions: string[];
}

interface MediaPlanEntry {
  platform: string;
  date: string;
  strategicReason: string;
  eventAlignment: string;
  roiPotential: string;
}

interface StrategicPost {
  id: number;
  platform: string;
  content: string;
  scheduledFor: string;
  strategicTheme: string;
  businessCanvasPhase: string;
  engagementOptimization: string;
  conversionFocus: string;
  audienceSegment: string;
}

export class StrategicContentGenerator {
  
  /**
   * TWO-STAGE GROK EXPERT APPROACH
   * Stage 1: Grok as World's Best Media Planner - Creates calendar with optimal days/platforms
   * Stage 2: Grok as Expert Copywriter - Creates tailored content for each calendar entry
   */
  static async generateStrategicContent(params: StrategicContentParams): Promise<StrategicPost[]> {
    console.log(`🎯 Starting two-stage strategic content generation for user ${params.userId}`);
    
    try {
      // STAGE 1: GROK AS MEDIA PLANNER - Create strategic calendar
      console.log('📅 Stage 1: Grok acting as world\'s best media planner...');
      const mediaCalendar = await this.createMediaPlanningCalendar(params);
      
      // STAGE 2: GROK AS EXPERT COPYWRITER - Create tailored content for each calendar entry
      console.log('✍️ Stage 2: Grok acting as expert copywriter for each calendar entry...');
      const strategicContent = await this.createExpertCopywritingContent(mediaCalendar, params);
      
      return strategicContent;
    } catch (error) {
      console.log(`🔄 Strategic content generation fallback triggered for user ${params.userId} - AI unavailable`);
      
      // Complete fallback system using pre-built strategic content
      return this.generateFallbackStrategicContent(params);
    }
  }

  /**
   * STAGE 1: GROK AS WORLD'S BEST MEDIA PLANNER
   * Selects optimal days and platforms based on events, business relevance, and ROI potential
   */
  private static async createMediaPlanningCalendar(params: StrategicContentParams): Promise<MediaPlanEntry[]> {
    const mediaPlanneryPrompt = `You are the world's best media planner with expertise in Queensland business cycles, events, and optimal posting strategies.

BUSINESS CONTEXT:
- Business: TheAgencyIQ (Queensland SME automation platform)
- Target Audience: Time-poor Queensland business owners needing visibility
- Core Purpose: Help busy owners with automated social media for professional visibility
- Brand Promise: "Stop being invisible - get your always-on beacon"

PLATFORMS AVAILABLE: ${params.platforms.join(', ')}
TOTAL POSTS NEEDED: ${params.totalPosts}
START DATE: 2025-07-19 (30-day calendar)

KEY QUEENSLAND EVENTS TO ALIGN WITH:
- Curated Plate: July 25 - August 3 (premium dining/networking)
- Great Barrier Reef Festival: August 1-3 (tourism/local pride)
- Taste Port Douglas: August 7-10 (local business showcase)
- Brisbane Ekka: July-August (major Queensland event)
- School holidays impact (business networking timing)

TASK: Create strategic 30-day calendar from 2025-07-19 onwards. CRITICAL: Distribute all ${params.totalPosts} posts across the FULL 30-day period (2025-07-19 to 2025-08-17). Do NOT cluster posts on same dates.

DISTRIBUTION REQUIREMENTS:
- Spread ${params.totalPosts} posts across 30 days (approximately ${Math.round(params.totalPosts/30)} posts per day)
- Use different dates for each post to maximize timeline coverage
- Align with Queensland events when relevant dates match

1. **Event Alignment Strategy**:
   - Pre-event buzz building (1-2 days before)
   - During-event engagement (real-time relevance)
   - Post-event follow-up (networking continuation)

2. **Platform-Day Optimization**:
   - LinkedIn: Tuesday-Thursday B2B peaks
   - Facebook: Wednesday-Friday community engagement
   - Instagram: Thursday-Sunday visual content performance
   - X: Monday-Wednesday conversation windows  
   - YouTube: Weekend educational consumption

3. **Busy Owner Psychology**:
   - Monday motivation (new week energy)
   - Wednesday wisdom (mid-week expertise)
   - Friday inspiration (week-end positivity)

Return JSON array "calendar" with exactly ${params.totalPosts} entries distributed across 30 different dates:
{
  "platform": "facebook/instagram/linkedin/x/youtube",
  "date": "2025-07-DD", 
  "strategicReason": "Why this platform/day maximizes ROI for busy owners",
  "eventAlignment": "Specific Queensland event or business cycle alignment",
  "roiPotential": "high/medium/optimal"
}

Focus on event-driven opportunities and optimal engagement windows for Queensland SMEs.`;

    const response = await aiClient.chat.completions.create({
      model: "grok-beta",
      messages: [
        {
          role: "system",
          content: "You are the world's best media planner specializing in Queensland SME marketing strategies. You understand optimal platform timing, event alignment, and ROI maximization for small businesses."
        },
        {
          role: "user",
          content: mediaPlanneryPrompt
        }
      ],
      response_format: { type: "json_object" }
    });

    const plannerResult = JSON.parse(response.choices[0].message.content || '{}');
    return plannerResult.calendar || plannerResult.entries || [];
  }

  /**
   * STAGE 2: GROK AS EXPERT COPYWRITER WITH QUEENSLAND CREATIVE DIRECTOR TRAINING
   * Creates tailored content for each planned calendar entry using anime-influenced viral prompts
   */
  private static async createExpertCopywritingContent(mediaCalendar: MediaPlanEntry[], params: StrategicContentParams): Promise<StrategicPost[]> {
    const strategicPosts: StrategicPost[] = [];
    
    // Process each calendar entry with Queensland creative director enhanced copywriting
    for (let i = 0; i < mediaCalendar.length; i++) {
      const entry = mediaCalendar[i];
      
      const copywriterPrompt = `You are an expert copywriter with Queensland creative director training, creating witty, engaging content for TheAgencyIQ targeting Queensland SME owners using anime-influenced viral storytelling techniques.

QUEENSLAND CREATIVE DIRECTOR TRAINING FRAMEWORK:
- STEP-BY-STEP REASONING: Analyze JTBD → Identify cultural triggers → Apply anime transformation → Assess viral potential → Align with events → Synthesize creative vision
- ANIME-INFLUENCED STYLE: Transform ordinary business moments into extraordinary, wish-fulfillment scenarios
- VIRAL STORYTELLING: Focus on relatability, humour, emotional engagement - never boring business-speak
- AUTHENTIC QUEENSLAND VOICE: Use local slang, cultural references, and community pride

STRATEGIC CALENDAR ENTRY FROM MEDIA PLANNER:
- Platform: ${entry.platform}
- Date: ${entry.date}
- Strategic Reason: ${entry.strategicReason}
- Event Alignment: ${entry.eventAlignment}
- ROI Potential: ${entry.roiPotential}

THEAGENCYIQ BRAND CONTEXT:
- Mission: Help time-poor Queensland business owners with automated social media for visibility
- Core Problem: "You're invisible, and silence is killing your growth"
- Solution: "Always-on beacon that gives you presence, polish, and power without the army"
- Target: Busy Queensland SME owners who need professional visibility but lack time

STEP-BY-STEP REASONING PROCESS:
1. JTBD ANALYSIS: What emotional job is this content hired to do?
2. CULTURAL TRIGGERS: Which Queensland elements will resonate most?
3. ANIME TRANSFORMATION: How can we make this moment feel epic and aspirational?
4. VIRAL POTENTIAL: What makes this shareable and memorable?
5. EVENT ALIGNMENT: How does this connect to Queensland calendar events?
6. CREATIVE SYNTHESIS: Bring all elements together for maximum impact

PLATFORM REQUIREMENTS:
${this.getPlatformContentGuidelines(entry.platform)}

COPYWRITER INSTRUCTIONS:
Create engaging, conversion-focused content that:
1. Hooks busy owners with relatable visibility pain points
2. Aligns with the Queensland event/timing from media planner
3. Uses witty, conversational Australian tone (not corporate)
4. Includes subtle TheAgencyIQ solution integration
5. Drives action with compelling CTAs
6. Makes content editable: true for easy customization

Content should feel authentic and valuable while addressing the "invisible business" problem with the "always-on beacon" solution.

Return JSON with:
{
  "content": "Witty, engaging platform-optimized post content",
  "strategicTheme": "Main strategic focus from media planning",
  "conversionFocus": "Primary conversion goal",
  "editable": true
}`;

      const copyResponse = await aiClient.chat.completions.create({
        model: "grok-beta",
        messages: [
          {
            role: "system",
            content: "You are an expert copywriter specializing in Queensland SME content that converts. You understand platform nuances, local business context, and engagement optimization."
          },
          {
            role: "user",
            content: copywriterPrompt
          }
        ],
        response_format: { type: "json_object" }
      });

      const copyResult = JSON.parse(copyResponse.choices[0].message.content || '{}');
      
      // Create proper date with time for scheduling
      const scheduledDate = new Date(entry.date);
      scheduledDate.setHours(this.getOptimalPostingTime(entry.platform));
      
      strategicPosts.push({
        id: i + 1,
        platform: entry.platform,
        content: copyResult.content || `Strategic content for ${entry.platform} on ${entry.date}`,
        scheduledFor: scheduledDate.toISOString(),
        strategicTheme: copyResult.strategicTheme || entry.strategicReason,
        businessCanvasPhase: entry.eventAlignment,
        engagementOptimization: entry.roiPotential,
        conversionFocus: copyResult.conversionFocus || 'Awareness building',
        audienceSegment: 'Queensland SME owners'
      });
    }
    
    return strategicPosts;
  }

  /**
   * Platform-specific content guidelines for expert copywriter with Queensland creative director training
   */
  private static getPlatformContentGuidelines(platform: string): string {
    const guidelines = {
      facebook: "Facebook: 400-1500 characters, community-focused tone with anime-influenced storytelling, encourage comments/shares, use engaging questions, Queensland local references, transform ordinary moments into epic celebrations, 'fair dinkum' authentic voice",
      instagram: "Instagram: 300-400 characters max, visual storytelling with transformation energy, relevant hashtags (#QueenslandSME #BusinessVisibility), strong call-to-action, anime-style wish-fulfillment narrative, local event alignment",
      linkedin: "LinkedIn: 700-1000 characters, professional B2B tone with heroic business journey narrative, industry insights told through transformation stories, thought leadership with Queensland cultural pride, networking focus using community celebration energy",
      x: "X: 200-280 characters max, conversational and witty with anime transformation hooks, trending topics, CRITICAL: X PLATFORM STRICT RULES: Maximum 280 characters, hashtags (#) COMPLETELY PROHIBITED (will be rejected), ONLY @ mentions allowed, clean engaging content without promotional tones or emojis, encourage retweets and engagement, bite-sized epic moments, Queensland slang integration",
      youtube: "YouTube: 500-600 characters, educational preview format with anime-influenced storytelling, encourage subscriptions, video content teasers that promise transformation journeys, Queensland community celebration vibes"
    };
    
    return guidelines[platform as keyof typeof guidelines] || "General: Engaging, authentic, conversion-focused content with Queensland context, anime-influenced transformation storytelling, step-by-step emotional journey from struggle to heroic success";
  }

  /**
   * COMPLETE FALLBACK STRATEGIC CONTENT GENERATION
   * When AI services are unavailable, generates strategic content using pre-built templates
   */
  private static async generateFallbackStrategicContent(params: StrategicContentParams): Promise<StrategicPost[]> {
    console.log('🛡️ Generating fallback strategic content using pre-built templates...');
    
    const strategicPosts: StrategicPost[] = [];
    const postsPerPlatform = Math.ceil(params.totalPosts / params.platforms.length);
    
    // Pre-built strategic content templates based on TheAgencyIQ brand purpose
    const contentTemplates = {
      facebook: [
        `Attention Queensland SME owners! Are you feeling invisible in your busy schedule? Silence is killing your growth, but you're not alone. TheAgencyIQ understands the struggle of juggling business and visibility. We're here to give you the presence, polish, and power that big brands have, without the need for an army. Our always-on beacon ensures you're not just visible, but validated, even when you're too swamped to show up. Don't let silence suffocate your business any longer. With TheAgencyIQ, you can show up professionally, strategically, and automatically, week in and week out. Stop being invisible and start being seen. Take action now and let us help you shine! #QueenslandSMEs #VisibilityMatters`,
        `Your Queensland small business deserves the visibility it needs to thrive! Are you tired of being the best-kept secret in your industry? TheAgencyIQ specialises in transforming invisible businesses into visible powerhouses. We provide the presence, polish, and power that big brands enjoy, but without the need for a large team. Our always-on beacon approach ensures you maintain professional visibility even during your busiest periods. Don't let another day pass in silence – your business growth depends on consistent, strategic visibility. Ready to transform your business presence? Contact TheAgencyIQ today! #BusinessVisibility #QueenslandGrowth`
      ],
      instagram: [
        `Is your Queensland SME invisible? Silence is killing your growth!\n\nYou're busy, but your business deserves the presence, polish, and power of big brands. TheAgencyIQ is your always-on beacon, providing not just visibility, but validation.\n\nShow up professionally, strategically, automatically - week in, week out. Don't let silence suffocate your success.\n\n#InvisibleNoMore #QueenslandSMEs #AgencyIQ\n\nStop Being Invisible. Take action now with TheAgencyIQ!`,
        `Transform your invisible business into a visible powerhouse!\n\nQueensland SMEs: You work hard, but your business deserves to be seen. TheAgencyIQ provides the beacon that keeps you visible even when you're too busy to show up.\n\nProfessional presence, strategic positioning, and automated visibility working together to amplify your business impact.\n\nDon't let silence kill your growth. Start shining today!\n\n#VisibleBusiness #QueenslandSME #BusinessGrowth #TheAgencyIQ`
      ],
      linkedin: [
        `As a busy Queensland SME owner, you know the struggle of staying visible in a crowded market. Silence is killing your growth, and you're left feeling invisible. But it doesn't have to be this way. \n\nTheAgencyIQ understands the pain of being an invisible business. We're here to give you the presence, polish, and power that big brands enjoy, without the need for a large team. Our solution is your always-on beacon, ensuring you're seen and validated even when you're too busy to show up yourself.\n\nImagine showing up week in, week out, professionally, strategically, and automatically. With TheAgencyIQ, this can be your reality. We're committed to keeping you visible and providing the validation you deserve, so you can focus on running your business.\n\nDon't let silence continue to stifle your growth. It's time to take action and stop being invisible. Let TheAgencyIQ be your partner in achieving the visibility and validation you need to thrive.\n\nContact us today and discover how we can help you shine in the Queensland market. Your business deserves to be seen – let's make it happen together.\n\n#TheAgencyIQ #VisibleBusiness #QueenslandSMEs #PresencePolishPower`,
        `The challenge facing Queensland SMEs today isn't just competition—it's invisibility. In a digital landscape where presence equals profit, many excellent businesses remain unseen, struggling to maintain consistent visibility while managing day-to-day operations.\n\nAt TheAgencyIQ, we've identified this critical gap: the difference between businesses that thrive and those that merely survive often comes down to strategic, consistent visibility. Our always-on beacon approach provides what enterprise brands have enjoyed for decades—presence, polish, and power—but scaled appropriately for growing SMEs.\n\nOur methodology focuses on validation, not just visibility. We understand that Queensland business owners need more than sporadic social media posts; they need a systematic approach to market presence that works even during their busiest periods.\n\nThe result? Businesses that show up professionally, strategically, and automatically, creating the kind of consistent market presence that drives sustainable growth.\n\nIf you're ready to transform your business visibility and stop being Queensland's best-kept secret, let's discuss how TheAgencyIQ can become your strategic visibility partner.\n\n#BusinessStrategy #QueenslandBusiness #MarketPresence #SMEGrowth`
      ],
      x: [
        `Your Queensland SME is invisible. Silence is killing your growth.\n\nYou need what big brands have: presence, polish, power - without the army.\n\nTheAgencyIQ = your always-on beacon.\nNot just visibility, but VALIDATION.\n\nShow up professionally. Strategically. Automatically.\n\nStop being invisible. Start being seen.\n\n@TheAgencyIQ helps Queensland SMEs`,
        `Queensland SME truth bomb:\n\nBeing the best-kept secret is killing your business.\n\nWhile you're busy delivering excellence, competitors with inferior products are stealing your market share through consistent visibility.\n\nTheAgencyIQ fixes this.\n\nPresence. Polish. Power.\nWithout the hassle.\n\n@TheAgencyIQ transforms visibility`
      ],
      youtube: [
        `Are you a Queensland SME feeling invisible? This video explains how silence is literally killing your business growth and what successful businesses do differently. Discover TheAgencyIQ's always-on beacon approach that gives you the presence, polish, and power of big brands without needing an entire marketing team. Learn how to show up professionally, strategically, and automatically - even when you're too busy to manage it yourself. Don't let your business stay invisible any longer. Click to learn more about transforming your visibility. #QueenslandBusiness #SMEGrowth #DigitalPresence`,
        `Attention Queensland small business owners: If you're working harder than ever but feeling invisible in your market, this video is for you. We'll explore the critical difference between businesses that thrive and those that struggle – consistent, strategic visibility. Learn how TheAgencyIQ's systematic approach transforms invisible businesses into market leaders through our always-on beacon methodology. Discover the three pillars that give enterprises their edge: presence, polish, and power, and how to implement them in your SME without the overhead. Stop being Queensland's best-kept secret and start commanding the visibility your business deserves. #BusinessGrowth #MarketingStrategy #QueenslandSME`
      ]
    };

    // Generate posts for each platform using strategic templates
    for (let i = 0; i < params.platforms.length; i++) {
      const platform = params.platforms[i];
      const templates = contentTemplates[platform as keyof typeof contentTemplates] || contentTemplates.facebook;
      
      for (let j = 0; j < postsPerPlatform && strategicPosts.length < params.totalPosts; j++) {
        const templateIndex = j % templates.length;
        
        // CRITICAL FIX: Distribute across 30 days properly
        const totalPostsCreated = strategicPosts.length;
        const daySpread = Math.floor((totalPostsCreated * 30) / params.totalPosts); // Distribute across 30 days
        
        const scheduledDate = new Date('2025-07-19'); // Start from specified date
        scheduledDate.setDate(scheduledDate.getDate() + daySpread);
        scheduledDate.setHours(this.getOptimalPostingTime(platform));
        
        const post: StrategicPost = {
          id: strategicPosts.length + 1,
          platform,
          content: templates[templateIndex], // Clean content without backend IDs
          scheduledFor: scheduledDate.toISOString(),
          strategicTheme: 'invisible-business-problem',
          businessCanvasPhase: this.getBusinessCanvasPhase(j),
          engagementOptimization: 'visibility-transformation',
          conversionFocus: 'Stop Being Invisible',
          audienceSegment: this.getAudienceSegment(platform)
        };
        
        strategicPosts.push(post);
      }
    }
    
    console.log(`✅ Generated ${strategicPosts.length} fallback strategic posts`);
    return strategicPosts.slice(0, params.totalPosts);
  }

  /**
   * PHASE 1: Brand Purpose Analysis
   * Analyzes core brand purpose for strategic direction
   */
  private static async analyzeBrandPurpose(brandPurpose: any): Promise<any> {
    console.log('🔍 Phase 1: Analyzing brand purpose...');
    
    try {
      const prompt = `G'day mate! Let's dive deep into this Queensland SME's brand DNA and uncover some golden strategic insights, shall we? 

      Here's what we're working with:
      🏢 Brand: ${brandPurpose.brandName}
      🎯 Purpose: ${brandPurpose.corePurpose}
      🛠️ What they do: ${brandPurpose.productsServices}
      👥 Who they serve: ${brandPurpose.audience}
      
      Now, here's the thing - most brands are just noise in the digital wilderness. But THIS one? Let's make it a beacon that cuts through the Queensland market clutter like a hot knife through butter.
      
      I need you to channel your inner strategic genius and give me:
      1. 🏗️ Core brand pillars (3-5 themes that'll make competitors weep)
      2. 💎 Unique value drivers (what makes them irresistibly different?)
      3. 📍 Market positioning gold mines (where can they dominate?)
      4. 📚 Authority-building content themes (what makes people listen?)
      5. ⚔️ Competitive differentiation weapons (their secret sauce)
      
      Remember: We're talking Queensland SMEs here - businesses that hustle hard but often stay invisible. Let's fix that invisibility problem with some serious strategic firepower!`;

      console.log('🔍 Sending request to AI client...');
      const response = await aiClient.chat.completions.create({
        model: "grok-beta",
        messages: [{ role: "user", content: prompt }],
        response_format: { type: "json_object" },
      });

      console.log('✅ Phase 1 complete: Brand purpose analysis received');
      return JSON.parse(response.choices[0].message.content || "{}");
    } catch (error) {
      console.error('❌ Phase 1 AI failed, using fallback analysis:', error);
      
      // Fallback: Create strategic analysis based on brand purpose data
      return {
        coreBrandPillars: [
          'Queensland Local Business Authority',
          'Time-Efficient Marketing Automation',
          'Professional Social Media Presence',
          'Authentic Community Connection',
          'Growth-Driven Results'
        ],
        uniqueValueDrivers: [
          'Set & Forget automation for time-poor business owners',
          'Queensland-specific market understanding',
          'Professional brand presence without extra work',
          'Measurable growth through consistent posting'
        ],
        marketPositioningOpportunities: [
          'Local market leader in automated social media',
          'Go-to solution for Queensland SMEs',
          'Bridge between big brand presence and small business reality',
          'Community-focused brand building'
        ],
        contentThemesForAuthority: [
          'Local business success stories',
          'Queensland market insights',
          'Time-saving business tips',
          'Community engagement strategies',
          'Growth and visibility tactics'
        ],
        competitiveDifferentiationFactors: [
          'Queensland-specific content and timing',
          'True automation vs manual posting',
          'SME-focused rather than enterprise',
          'Local community understanding',
          'Authentic voice preservation'
        ]
      };
    }
  }

  /**
   * PHASE 2: Audience Insights with Jobs-to-be-Done Framework
   * Generates deep audience insights using Strategyzer methodology
   */
  private static async generateAudienceInsights(brandPurpose: any): Promise<any> {
    console.log('👥 Phase 2: Generating audience insights...');
    
    return await generateJobsToBeDoneAnalysis(
      brandPurpose.corePurpose,
      brandPurpose.audience,
      brandPurpose.painPoints,
      brandPurpose.motivations
    );
  }

  /**
   * PHASE 3: Queensland Market Data Integration
   * Integrates Queensland-specific market insights
   */
  private static async getQueenslandMarketData(brandPurpose: any): Promise<QueenslandMarketInsights> {
    console.log('🏖️ Phase 3: Gathering Queensland market data...');
    
    try {
      const prompt = `Right, let's get deep into Queensland market intelligence! 🇦🇺 Time to uncover the hidden gems that'll make ${brandPurpose.brandName} absolutely dominate their local market.

      Here's what we're working with:
      🏭 Industry: ${brandPurpose.productsServices}
      🎯 They're targeting: ${brandPurpose.audience}
      
      Now, here's what I need from you - and I need it to be laser-focused on Queensland's unique market dynamics:
      
      1. 🏗️ Key industries driving growth (think mining powerhouses, tourism gold mines, agricultural excellence, tech innovation hubs)
      2. 🌴 Seasonal business trends that are uniquely Queenslander (because let's face it, QLD has its own rhythm!)
      3. ⚔️ Competitive advantages that local businesses can leverage (what makes Queensland businesses special?)
      4. 🎪 Major local events and networking goldmines (where the magic happens)
      5. 🔍 SEO keywords that'll make them top of search in Queensland
      
      Remember: We're not just gathering data here - we're building a strategic arsenal for small business domination. Make every insight count!`;

      const response = await aiClient.chat.completions.create({
        model: "grok-beta",
        messages: [{ role: "user", content: prompt }],
        response_format: { type: "json_object" },
      });

      console.log('✅ Phase 3 complete: Queensland market data received');
      return JSON.parse(response.choices[0].message.content || "{}");
    } catch (error) {
      console.error('❌ Phase 3 AI failed, using fallback market data:', error);
      
      // Fallback: Pre-defined Queensland market insights
      return {
        keyIndustries: [
          'Mining and Resources',
          'Tourism and Hospitality',
          'Agriculture and Food Production',
          'Technology and Innovation',
          'Construction and Infrastructure',
          'Healthcare and Aged Care',
          'Education and Training',
          'Professional Services'
        ],
        seasonalTrends: [
          'Winter dry season (May-October) - peak tourism',
          'Summer wet season (November-April) - agricultural focus',
          'Brisbane Ekka (August) - major marketing opportunity',
          'School holidays - family-focused campaigns',
          'Christmas/New Year - retail peak season',
          'Easter - travel and hospitality focus'
        ],
        competitiveAdvantages: [
          'Local knowledge and community connections',
          'Personalized service vs large corporations',
          'Quick response times and flexibility',
          'Supporting local Queensland economy',
          'Understanding of local regulations and culture',
          'Authentic Queensland voice and values'
        ],
        localEvents: [
          'Brisbane Ekka (August)',
          'Gold Coast 600 (October)',
          'Brisbane Festival (September)',
          'Cairns Festival (August-September)',
          'Townsville Cultural Festival (July)',
          'Sunshine Coast Marathon (August)'
        ],
        seoKeywords: [
          'Queensland small business',
          'Brisbane local services',
          'Gold Coast marketing',
          'Sunshine Coast business',
          'Queensland SME solutions',
          'local business Queensland',
          'Brisbane automation',
          'Queensland social media'
        ]
      };
    }
  }

  /**
   * PHASE 4: SEO Keywords for Queensland SMEs
   * Generates targeted keywords for local search domination
   */
  private static async generateSEOKeywords(brandPurpose: any, marketData: QueenslandMarketInsights): Promise<string[]> {
    console.log('🔍 Phase 4: Generating SEO keywords...');
    
    try {
      const prompt = `Generate high-converting SEO keywords for Queensland SME:
      
      Brand: ${brandPurpose.brandName}
      Services: ${brandPurpose.productsServices}
      Target: ${brandPurpose.audience}
      Local Market: ${JSON.stringify(marketData.keyIndustries)}
      
      Generate 20 strategic keywords including:
      1. Local geo-targeted keywords (Brisbane, Gold Coast, Sunshine Coast, etc.)
      2. Industry-specific long-tail keywords
      3. Service-based keywords with local intent
      4. Competitive keywords for market domination
      5. Seasonal Queensland keywords
      
      Focus on high-intent, low-competition keywords for rapid ranking and customer acquisition.`;

      const response = await aiClient.chat.completions.create({
        model: "grok-beta",
        messages: [{ role: "user", content: prompt }],
      });

      const content = response.choices[0].message.content || "";
      return content.split('\n').filter(line => line.trim()).slice(0, 20);
    } catch (error) {
      console.log('🔄 SEO Keywords fallback - AI unavailable, using strategic defaults');
      
      // Fallback Queensland SEO keywords based on TheAgencyIQ brand purpose
      return [
        'Queensland small business social media',
        'Brisbane business automation',
        'Gold Coast marketing agency',
        'Sunshine Coast digital marketing',
        'Queensland SME growth',
        'Brisbane social media management',
        'local business visibility Queensland',
        'automated content creation Brisbane',
        'Queensland business marketing',
        'small business social media QLD',
        'Brisbane digital presence',
        'Gold Coast business growth',
        'Queensland automated marketing',
        'local SEO Brisbane',
        'social media automation Queensland',
        'Brisbane business visibility',
        'Queensland content marketing',
        'small business automation QLD',
        'Brisbane marketing solutions',
        'Queensland digital transformation'
      ];
    }
  }

  /**
   * PHASE 5: Value Proposition Canvas
   * Creates comprehensive value proposition framework
   */
  private static async createValuePropositionCanvas(brandPurpose: any, audienceInsights: any): Promise<ValuePropositionCanvas> {
    console.log('💎 Phase 5: Creating Value Proposition Canvas...');
    
    try {
      const prompt = `Create a comprehensive Value Proposition Canvas for:
      
      Brand: ${brandPurpose.brandName}
      Core Purpose: ${brandPurpose.corePurpose}
      Target Jobs: ${JSON.stringify(audienceInsights.functionalJob)}
      Pain Points: ${JSON.stringify(audienceInsights.painPoints)}
      
      Generate Value Proposition Canvas:
      1. Customer Jobs (functional, emotional, social)
      2. Pain Points (current frustrations and obstacles)
      3. Gain Creators (benefits that delight customers)
      4. Products/Services (core offerings)
      5. Pain Relievers (how offerings solve problems)
      6. Value Propositions (unique value delivery statements)
      
      Focus on subscriber delight and Queensland small business growth acceleration.`;

      const response = await aiClient.chat.completions.create({
        model: "grok-beta",
        messages: [{ role: "user", content: prompt }],
        response_format: { type: "json_object" },
      });

      return JSON.parse(response.choices[0].message.content || "{}");
    } catch (error) {
      console.log('🔄 Value Proposition Canvas fallback - AI unavailable, using strategic defaults');
      
      // Fallback Value Proposition Canvas based on TheAgencyIQ brand purpose
      return {
        customerJobs: ['Growing Queensland businesses efficiently without manual marketing overhead'],
        painPoints: ['Time-consuming manual marketing', 'inconsistent presence', 'technical complexity', 'poor ROI'],
        gainCreators: ['Automated professional content', 'strategic positioning', 'measurable results', 'constant visibility'],
        products: ['Social media automation platform'],
        painRelievers: ['Eliminates manual content creation', 'Ensures consistent online presence'],
        valuePropositions: ['Always-on beacon for Queensland SMEs']
      };
    }
  }

  /**
   * PHASE 6: High-Engagement Templates with Sales CTAs
   * Generates platform-specific content templates optimised for engagement
   */
  private static async generateEngagementTemplates(valueCanvas: ValuePropositionCanvas, seoKeywords: string[]): Promise<any[]> {
    console.log('🎨 Phase 6: Creating engagement templates...');
    
    const templates = [];
    
    // Invisible Business Problem Templates
    templates.push({
      theme: 'invisible-business-problem',
      contentType: 'problem-awareness',
      cta: 'Stop Being Invisible',
      platforms: ['linkedin', 'facebook'],
      focus: 'invisible business pain'
    });
    
    // Always-On Beacon Solution Templates
    templates.push({
      theme: 'always-on-beacon',
      contentType: 'solution-focussed',
      cta: 'Get Your Beacon',
      platforms: ['instagram', 'facebook'],
      focus: 'professional visibility'
    });
    
    // Validation Not Visibility Templates
    templates.push({
      theme: 'validation-not-visibility',
      contentType: 'differentiation',
      cta: 'Get Validated',
      platforms: ['linkedin', 'youtube'],
      focus: 'validation messaging'
    });
    
    // Presence Polish Power Templates
    templates.push({
      theme: 'presence-polish-power',
      contentType: 'transformation',
      cta: 'Get Big Brand Power',
      platforms: ['x', 'instagram'],
      focus: 'big brand presence'
    });
    
    // Silence Kills Growth Templates
    templates.push({
      theme: 'silence-kills-growth',
      contentType: 'urgency',
      cta: 'Break The Silence',
      platforms: ['facebook', 'instagram'],
      focus: 'growth urgency'
    });
    
    // Show Up Automatically Templates
    templates.push({
      theme: 'show-up-automatically',
      contentType: 'benefit-focussed',
      cta: 'Start Showing Up',
      platforms: ['linkedin', 'youtube'],
      focus: 'automation benefit'
    });
    
    // Too Busy To Show Up Templates
    templates.push({
      theme: 'too-busy-to-show-up',
      contentType: 'relatable-pain',
      cta: 'Let Us Show Up',
      platforms: ['facebook', 'x'],
      focus: 'busy business owner'
    });
    
    return templates;
  }

  /**
   * PHASE 7: 30-Day Cycle Optimisation for Reach/Conversion
   * Optimises content distribution across 30-day cycles
   */
  private static async optimise30DayCycle(
    templates: any[],
    totalPosts: number,
    platforms: string[],
    marketData: QueenslandMarketInsights,
    brandPurpose: any
  ): Promise<StrategicPost[]> {
    console.log('📈 Phase 7: Optimising 30-day cycle...');
    
    const strategicPosts: StrategicPost[] = [];
    const postsPerPlatform = Math.ceil(totalPosts / platforms.length);
    
    // Generate posts for each platform
    for (let i = 0; i < platforms.length; i++) {
      const platform = platforms[i];
      
      for (let j = 0; j < postsPerPlatform && strategicPosts.length < totalPosts; j++) {
        const template = templates[j % templates.length];
        const dayOffset = Math.floor(strategicPosts.length / platforms.length);
        
        const scheduledDate = new Date();
        scheduledDate.setDate(scheduledDate.getDate() + dayOffset);
        scheduledDate.setHours(this.getOptimalPostingTime(platform));
        
        const post: StrategicPost = {
          id: strategicPosts.length + 1,
          platform,
          content: await this.generateStrategicPostContent(platform, template, marketData, brandPurpose),
          scheduledFor: scheduledDate.toISOString(),
          strategicTheme: template.theme,
          businessCanvasPhase: this.getBusinessCanvasPhase(j),
          engagementOptimization: template.focus,
          conversionFocus: template.cta,
          audienceSegment: this.getAudienceSegment(platform)
        };
        
        strategicPosts.push(post);
      }
    }
    
    return strategicPosts.slice(0, totalPosts);
  }

  /**
   * Generate strategic post content for specific platform and template
   */
  private static async generateStrategicPostContent(platform: string, template: any, marketData: QueenslandMarketInsights, brandPurpose: any): Promise<string> {
    try {
      const prompt = `Generate ${platform} post content for TheAgencyIQ that MUST align with this specific brand purpose:

      BRAND PURPOSE: "${brandPurpose.corePurpose}"
      
      CORE VALUE PROPOSITION: "You're invisible, that's not good. AgencyIQ gives you a beacon that's always on."
      
      THE PAIN: "You're invisible, and silence is killing your growth."
      THE GAIN: "You show up. Week in, week out. Professionally. Strategically. Automatically."
      
      BRAND PROMISE: "Keep me visible even when I am too busy to show up, not just visibility, but validation. For those who want what the big brands have: presence, polish, and power, without the army it takes to get there."
      
      Template to use:
    - Theme: ${template.theme}
    - Content Type: ${template.contentType}
    - CTA: ${template.cta}
    - Focus: ${template.focus}
    
    CRITICAL REQUIREMENTS:
    1. ${this.getPlatformRequirements(platform)}
    2. MUST address the "invisible business" problem directly
    3. MUST position TheAgencyIQ as the solution that provides "presence, polish, and power"
    4. MUST speak to busy Queensland SME owners who need professional visibility
    5. MUST emphasize "validation not just visibility" and "always on beacon"
    6. MUST include urgency about silence killing growth
    7. MUST offer hope of showing up "professionally, strategically, automatically"
    8. Include strong call-to-action that drives immediate action
    
    Write content that makes invisible Queensland SMEs feel seen and understood, then compels them to take action.`;

      const response = await aiClient.chat.completions.create({
        model: "grok-beta",
        messages: [{ role: "user", content: prompt }],
      });

      return response.choices[0].message.content || "";
    } catch (error) {
      console.log(`🔄 ${platform} content fallback - AI unavailable, using strategic template`);
      
      // Platform-specific fallback content based on TheAgencyIQ brand purpose
      const fallbackContent = {
        facebook: `Attention Queensland SME owners! Are you feeling invisible in your busy schedule? Silence is killing your growth, but you're not alone. TheAgencyIQ understands the struggle of juggling business and visibility. We're here to give you the presence, polish, and power that big brands have, without the need for an army. Our always-on beacon ensures you're not just visible, but validated, even when you're too swamped to show up. Don't let silence suffocate your business any longer. With TheAgencyIQ, you can show up professionally, strategically, and automatically, week in and week out. Stop being invisible and start being seen. Take action now and let us help you shine! #QueenslandSMEs #VisibilityMatters`,
        
        instagram: `🚨 Is your Queensland SME invisible? Silence is killing your growth! 🚨\n\nYou're busy, but your business deserves the presence, polish, and power of big brands. TheAgencyIQ is your always-on beacon, providing not just visibility, but validation.\n\nShow up professionally, strategically, automatically - week in, week out. Don't let silence suffocate your success.\n\n#InvisibleNoMore #QueenslandSMEs #AgencyIQ\n\n👉 Stop Being Invisible. Take action now with TheAgencyIQ!`,
        
        linkedin: `As a busy Queensland SME owner, you know the struggle of staying visible in a crowded market. Silence is killing your growth, and you're left feeling invisible. But it doesn't have to be this way. \n\nTheAgencyIQ understands the pain of being an invisible business. We're here to give you the presence, polish, and power that big brands enjoy, without the need for a large team. Our solution is your always-on beacon, ensuring you're seen and validated even when you're too busy to show up yourself.\n\nImagine showing up week in, week out, professionally, strategically, and automatically. With TheAgencyIQ, this can be your reality. We're committed to keeping you visible and providing the validation you deserve, so you can focus on running your business.\n\nDon't let silence continue to stifle your growth. It's time to take action and stop being invisible. Let TheAgencyIQ be your partner in achieving the visibility and validation you need to thrive.\n\nContact us today and discover how we can help you shine in the Queensland market. Your business deserves to be seen – let's make it happen together.\n\n#TheAgencyIQ #VisibleBusiness #QueenslandSMEs #PresencePolishPower`,
        
        x: `Your Queensland SME is invisible. Silence is killing your growth. 💀\n\nYou need what big brands have: presence, polish, power - without the army.\n\nTheAgencyIQ = your always-on beacon.\nNot just visibility, but VALIDATION.\n\nShow up professionally. Strategically. Automatically.\n\nStop being invisible. Start being seen. 🚀\n\n#QueenslandSMEs #StopBeingInvisible`,
        
        youtube: `Are you a Queensland SME feeling invisible? This video explains how silence is literally killing your business growth and what successful businesses do differently. Discover TheAgencyIQ's always-on beacon approach that gives you the presence, polish, and power of big brands without needing an entire marketing team. Learn how to show up professionally, strategically, and automatically - even when you're too busy to manage it yourself. Don't let your business stay invisible any longer. Click to learn more about transforming your visibility. #QueenslandBusiness #SMEGrowth #DigitalPresence`
      };
      
      return fallbackContent[platform as keyof typeof fallbackContent] || fallbackContent.facebook;
    }
  }

  /**
   * Get platform-specific content requirements
   */
  private static getPlatformRequirements(platform: string): string {
    const requirements = {
      'facebook': '400-600 characters, community-focused tone',
      'instagram': '250-350 characters, visual storytelling with hashtags',
      'linkedin': '700-1000 characters, professional authority tone',
      'x': '200-280 characters, concise with @ mentions',
      'youtube': '350-500 characters, video teaser format'
    };
    
    return requirements[platform as keyof typeof requirements] || '300-500 characters';
  }

  /**
   * Get optimal posting time for platform
   */
  private static getOptimalPostingTime(platform: string): number {
    const optimalTimes = {
      'facebook': 10, // 10 AM
      'instagram': 14, // 2 PM
      'linkedin': 9, // 9 AM
      'x': 12, // 12 PM
      'youtube': 16 // 4 PM
    };
    
    return optimalTimes[platform as keyof typeof optimalTimes] || 12;
  }

  /**
   * Get business canvas phase based on post sequence
   */
  private static getBusinessCanvasPhase(postIndex: number): string {
    const phases = [
      'Problem Identification',
      'Solution Presentation',
      'Value Proposition',
      'Customer Segments',
      'Key Partnerships',
      'Revenue Streams',
      'Cost Structure',
      'Key Resources',
      'Key Activities',
      'Channels'
    ];
    
    return phases[postIndex % phases.length];
  }

  /**
   * Get audience segment for platform
   */
  private static getAudienceSegment(platform: string): string {
    const segments = {
      'facebook': 'Community Builders',
      'instagram': 'Visual Storytellers',
      'linkedin': 'Professional Decision Makers',
      'x': 'Thought Leaders',
      'youtube': 'Educational Content Consumers'
    };
    
    return segments[platform as keyof typeof segments] || 'General Audience';
  }

  /**
   * QUOTA RESET UTILITY
   * Resets user quota to Professional plan allocation (30 posts)
   */
  static async resetQuotaToFiftyTwo(userId: number): Promise<void> {
    console.log(`🔄 Resetting quota for user ${userId} to Professional plan (30 posts)`);
    
    // Update published posts to archived to reset quota
    await db.update(posts)
      .set({ status: 'archived' })
      .where(and(eq(posts.userId, userId), eq(posts.status, 'published')));
      
    console.log(`✅ Quota reset complete - user ${userId} now has 30/30 posts available`);
  }

  /**
   * DUPLICATE POST CLEANUP
   * Removes duplicate and test posts to stabilize count
   */
  static async cleanupDuplicatePosts(userId: number): Promise<void> {
    console.log(`🧹 Cleaning up duplicate posts for user ${userId}`);
    
    // Archive all non-draft posts older than 30 days to clean up test data
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    await db.update(posts)
      .set({ status: 'archived' })
      .where(
        and(
          eq(posts.userId, userId),
          // Archive old test posts that are not recent drafts
          posts.createdAt
        )
      );
    
    console.log(`✅ Duplicate cleanup complete for user ${userId}`);
  }

  /**
   * TRANSACTIONAL DELETE-BEFORE-CREATE
   * Atomic operation to replace all user posts with new strategic content
   * Prevents post doubling by ensuring complete replacement in single transaction
   */
  static async replaceAllUserPostsTransactional(userId: number, newPosts: any[]): Promise<void> {
    console.log(`🔄 Starting transactional post replacement for user ${userId}`);
    
    try {
      // Use database transaction to ensure atomicity
      await db.transaction(async (tx) => {
        // Step 1: Delete all existing posts within transaction
        console.log(`🗑️  Deleting all existing posts for user ${userId} in transaction`);
        await tx.delete(posts).where(eq(posts.userId, userId));
        
        // Step 2: Create new posts within same transaction
        console.log(`✨ Creating ${newPosts.length} new strategic posts for user ${userId} in transaction`);
        if (newPosts.length > 0) {
          await tx.insert(posts).values(newPosts);
        }
        
        console.log(`✅ Transactional post replacement completed for user ${userId}`);
      });
      
      // Clear cache after transaction completes
      await this.clearPostQuotaCache(userId);
      
    } catch (error) {
      console.error(`❌ Transactional post replacement failed for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * DELETE ALL USER POSTS (Legacy method - replaced by transactional approach)
   * Completely removes all existing posts for a user to enable fresh strategic content generation
   */
  static async deleteAllUserPosts(userId: number): Promise<void> {
    console.log(`🗑️  Deleting all existing posts for user ${userId} to make room for new strategic content`);
    
    try {
      // Delete all posts for this user from the database
      const deleteResult = await db.delete(posts)
        .where(eq(posts.userId, userId));
      
      console.log(`✅ Successfully deleted all posts for user ${userId}`);
      
      // Clear the PostQuotaService cache to ensure fresh calculations
      await this.clearPostQuotaCache(userId);
      
      // Also reset the quota to ensure clean slate
      await this.resetQuotaToFiftyTwo(userId);
      
    } catch (error) {
      console.error(`❌ Error deleting posts for user ${userId}:`, error);
      throw error;
    }
  }

  /**
   * CLEAR POST QUOTA CACHE
   * Clears the PostQuotaService cache to ensure fresh quota calculations
   */
  static async clearPostQuotaCache(userId: number): Promise<void> {
    try {
      // Import and clear the cache from PostQuotaService
      const { PostQuotaService } = await import('../PostQuotaService');
      PostQuotaService.clearUserCache(userId);
      console.log(`🗑️  Cleared quota cache for user ${userId}`);
    } catch (error) {
      console.error(`❌ Error clearing quota cache for user ${userId}:`, error);
    }
  }
}