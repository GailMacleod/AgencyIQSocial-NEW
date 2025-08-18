import OpenAI from "openai";

const aiClient = new OpenAI({ 
  baseURL: "https://api.x.ai/v1", 
  apiKey: process.env.XAI_API_KEY 
});

export interface CMOTeamInsights {
  cmoStrategy: {
    marketPosition: string;
    competitiveAdvantage: string;
    brandDomination: string[];
    salesAnnihilation: string[];
  };
  creativeDirector: {
    visualIdentity: string;
    brandPersonality: string;
    contentThemes: string[];
    engagementHooks: string[];
  };
  copywriter: {
    messagingFramework: string;
    voiceTone: string;
    persuasionTactics: string[];
    conversionCopy: string[];
  };
  strategicAccountManager: {
    customerJourney: string[];
    touchpointOptimization: string[];
    conversionStrategy: string;
    relationshipBuilding: string[];
  };
  socialMediaExpert: {
    platformStrategy: { [platform: string]: string };
    contentCalendar: string[];
    engagementTactics: string[];
    viralPotential: string[];
  };
}

export interface JobsToBeDoneAnalysis {
  functionalJob: string;
  emotionalJob: string;
  socialJob: string;
  jobOutcome: string;
  painPoints: string[];
  gainCreators: string[];
  valueProposition: string;
  urgency: number; // 1-10 scale
  impact: number; // 1-10 scale
}

export interface BrandDominationStrategy {
  brandPurpose: string;
  targetMetrics: {
    salesTarget: number;
    conversionRate: number;
    timeToMarket: string;
  };
  keyHashtags: string[];
  seoKeywords: string[];
  competitorAnalysis: string[];
  marketDomination: string[];
}

export async function analyseCMOStrategy(brandPurpose: string, targetAudience: string): Promise<CMOTeamInsights> {
  const prompt = `As a CMO leading a strategic team, analyze this brand purpose: "${brandPurpose}" for target audience: "${targetAudience}"

Provide insights from each team member for unstoppable market domination:

CMO Strategy:
- Market positioning for brand domination
- Competitive advantages for sales annihilation  
- Strategic initiatives to explode visibility
- Revenue acceleration tactics

Creative Director:
- Visual identity that shatters competition
- Brand personality that magnetizes customers
- Content themes for viral engagement
- Visual hooks that stop scrolling

Copywriter:
- Messaging framework for conversion optimization
- Voice/tone for market authority
- Persuasion tactics for immediate action
- Copy formulas for sales annihilation

Strategic Account Manager:
- Customer journey optimization
- Touchpoint conversion strategies
- Relationship building for lifetime value
- Account expansion tactics

Social Media Expert:
- Platform-specific domination strategies
- Content calendar for explosive growth
- Engagement tactics for viral reach
- Algorithm optimization for maximum visibility

Focus on Queensland small business market with emphasis on immediate results and measurable ROI.`;

  const response = await aiClient.chat.completions.create({
    model: "grok-beta",
    messages: [{ role: "user", content: prompt }],
    response_format: { type: "json_object" },
  });

  return JSON.parse(response.choices[0].message.content || "{}");
}

export async function generateJobsToBeDoneAnalyse(
  brandPurpose: string,
  targetAudience: string,
  painPoints: string,
  motivations: string
): Promise<JobsToBeDoneAnalysis> {
  const prompt = `Using Strategyzer's Jobs-to-be-Done framework, analyze:

Brand Purpose: ${brandPurpose}
Target Audience: ${targetAudience}
Pain Points: ${painPoints}
Motivations: ${motivations}

Identify:
1. Functional Job (what task are customers trying to accomplish?)
2. Emotional Job (how do customers want to feel?)
3. Social Job (how do customers want to be perceived?)
4. Job Outcome (what does success look like?)
5. Pain Points (what frustrates customers?)
6. Gain Creators (what would delight customers?)
7. Value Proposition (unique value delivery)
8. Urgency Score (1-10: how urgent is this job?)
9. Impact Score (1-10: how impactful is solving this job?)

Focus on Queensland small business context with emphasis on rapid business growth and market domination.`;

  const response = await aiClient.chat.completions.create({
    model: "grok-beta",
    messages: [{ role: "user", content: prompt }],
    response_format: { type: "json_object" },
  });

  return JSON.parse(response.choices[0].message.content || "{}");
}

// Export alias for backward compatibility
export const generateJobsToBeDoneAnalysis = generateJobsToBeDoneAnalyse;

export async function createBrandDominationStrategy(
  brandPurpose: string,
  salesTarget: number = 10000,
  conversionRate: number = 3,
  hashtags: string[] = ['#QueenslandBusiness', '#TheAgencyIQ', '#SmallBusiness', '#DigitalMarketing']
): Promise<BrandDominationStrategy> {
  const prompt = `Create an unstoppable brand domination strategy for:

Brand Purpose: ${brandPurpose}
Sales Target: $${salesTarget}/month
Conversion Rate: ${conversionRate}%
Key Hashtags: ${hashtags.join(', ')}

Generate:
1. Market domination tactics for Queensland small businesses
2. SEO keywords for "brand domination" and "sales annihilation"
3. Competitor analysis and differentiation strategy
4. Content themes that explode visibility
5. Conversion optimization tactics
6. Social proof and authority building
7. Viral marketing strategies
8. Customer acquisition funnels
9. Retention and expansion strategies
10. Measurable KPIs for market leadership

Focus on immediate impact, scalable growth, and sustainable competitive advantage.`;

  const response = await aiClient.chat.completions.create({
    model: "grok-beta",
    messages: [{ role: "user", content: prompt }],
    response_format: { type: "json_object" },
  });

  const strategy = JSON.parse(response.choices[0].message.content || "{}");
  
  return {
    brandPurpose,
    targetMetrics: {
      salesTarget,
      conversionRate,
      timeToMarket: "10 minutes automated marketing setup"
    },
    keyHashtags: hashtags,
    seoKeywords: strategy.seoKeywords || [
      'brand domination', 'sales annihilation', 'marketing automation',
      'queensland business growth', 'small business marketing', 'digital transformation'
    ],
    competitorAnalysis: strategy.competitorAnalysis || [],
    marketDomination: strategy.marketDomination || []
  };
}

export async function generateUnstoppableContent(
  cmoInsights: CMOTeamInsights,
  jtbdAnalysis: JobsToBeDoneAnalysis,
  dominationStrategy: BrandDominationStrategy,
  platforms: string[],
  totalPosts: number
): Promise<any[]> {
  const prompt = `Transform this strategic analysis into ${totalPosts} unstoppable social media posts that annihilate competition and explode sales:

CMO STRATEGY: ${JSON.stringify(cmoInsights.cmoStrategy)}
CREATIVE DIRECTION: ${JSON.stringify(cmoInsights.creativeDirector)}
COPYWRITING FRAMEWORK: ${JSON.stringify(cmoInsights.copywriter)}
ACCOUNT STRATEGY: ${JSON.stringify(cmoInsights.strategicAccountManager)}
SOCIAL MEDIA TACTICS: ${JSON.stringify(cmoInsights.socialMediaExpert)}

JOBS-TO-BE-DONE INSIGHTS:
- Functional Job: ${jtbdAnalysis.functionalJob}
- Emotional Job: ${jtbdAnalysis.emotionalJob}
- Social Job: ${jtbdAnalysis.socialJob}
- Job Outcome: ${jtbdAnalysis.jobOutcome}
- Value Proposition: ${jtbdAnalysis.valueProposition}
- Urgency: ${jtbdAnalysis.urgency}/10
- Impact: ${jtbdAnalysis.impact}/10

BRAND DOMINATION STRATEGY:
- Sales Target: $${dominationStrategy.targetMetrics.salesTarget}/month
- Conversion Rate: ${dominationStrategy.targetMetrics.conversionRate}%
- Time to Market: ${dominationStrategy.targetMetrics.timeToMarket}
- SEO Keywords: ${dominationStrategy.seoKeywords.join(', ')}
- Key Hashtags: ${dominationStrategy.keyHashtags.join(', ')}

CONTENT REQUIREMENTS:
- Address the specific job-to-be-done with laser precision
- Use persuasion tactics from copywriting framework
- Implement creative themes for viral potential
- Include strategic account touchpoints
- Optimize for platform-specific engagement
- Drive immediate action toward sales targets
- Build brand authority and market domination
- Target Queensland small business ecosystem

Generate content that:
1. Saves businesses from obscurity
2. Automates 30 days of marketing in 10 minutes
3. Targets $10,000 sales/month with 3% conversion
4. Annihilates time-wasters
5. Explodes visibility
6. Shatters sales targets

Distribute across platforms: ${platforms.join(', ')}

Schedule starting June 11, 2025, 4:00 PM AEST with optimal timing for maximum engagement.

Return as JSON with "posts" array containing: platform, content, scheduledFor, strategicInsight, conversionFocus, dominationTactic.`;

  const response = await aiClient.chat.completions.create({
    model: "grok-beta",
    messages: [{ role: "user", content: prompt }],
    response_format: { type: "json_object" },
  });

  const result = JSON.parse(response.choices[0].message.content || "{}");
  return result.posts || [];
}

export async function adaptToAnyBrand(
  brandPurpose: string,
  targetAudience: string,
  painPoints: string,
  motivations: string,
  businessGoals: any,
  platforms: string[],
  totalPosts: number
): Promise<any[]> {
  // Step 1: Generate CMO team insights
  const cmoInsights = await analyseCMOStrategy(brandPurpose, targetAudience);
  
  // Step 2: Perform Jobs-to-be-Done analysis
  const jtbdAnalysis = await generateJobsToBeDoneAnalyse(
    brandPurpose, 
    targetAudience, 
    painPoints, 
    motivations
  );
  
  // Step 3: Create brand domination strategy
  const dominationStrategy = await createBrandDominationStrategy(brandPurpose);
  
  // Step 4: Generate unstoppable content
  const content = await generateUnstoppableContent(
    cmoInsights,
    jtbdAnalysis,
    dominationStrategy,
    platforms,
    totalPosts
  );
  
  return content;
}