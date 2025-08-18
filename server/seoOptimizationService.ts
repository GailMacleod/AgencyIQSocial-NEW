import fs from 'fs';
import path from 'path';

interface SeoConfig {
  config: {
    businessType: string;
    targetMarket: string;
    primaryLocation: string;
    serviceArea: string[];
    seoStrategy: {
      primaryKeywords: string[];
      longTailKeywords: string[];
      localSeoKeywords: string[];
      industrySpecificKeywords: string[];
      competitorKeywords: string[];
      trendingKeywords: string[];
    };
    contentOptimization: {
      titleTemplates: string[];
      metaDescriptionTemplates: string[];
      headerStructure: {
        h1Template: string;
        h2Templates: string[];
        h3Templates: string[];
      };
    };
    localSeoOptimization: {
      businessListings: {
        primaryAddress: string;
        serviceAreas: string[];
        categories: string[];
      };
      localContent: {
        locationPages: string[];
        localKeywordVariations: string[];
      };
    };
    contentStrategy: {
      blogTopics: string[];
      landingPageFocus: string[];
    };
    competitorAnalysis: {
      keyCompetitors: string[];
      competitiveAdvantages: string[];
    };
    voiceSearchOptimization: {
      conversationalKeywords: string[];
    };
  };
}

class SeoOptimizationService {
  private seoConfig: SeoConfig | null = null;

  constructor() {
    this.loadSeoConfig();
  }

  private loadSeoConfig(): void {
    try {
      const configPath = path.join(process.cwd(), 'ai_seo_business_optimized_config.json');
      const configData = fs.readFileSync(configPath, 'utf8');
      this.seoConfig = JSON.parse(configData);
      console.log('✅ SEO configuration loaded successfully');
    } catch (error) {
      console.error('Failed to load SEO configuration:', error);
    }
  }

  /**
   * Enhance content with SEO-optimized keywords for Queensland SME automation services
   */
  public optimizeContentForSeo(content: string, platform: string, targetKeyword?: string): string {
    if (!this.seoConfig) return content;

    const config = this.seoConfig.config;
    let optimizedContent = content;

    // Select appropriate keywords based on platform and content length
    const keywords = this.selectOptimalKeywords(platform, targetKeyword);
    
    // Integrate Queensland market-specific terms
    optimizedContent = this.integrateQueenslandMarketTerms(optimizedContent, platform);
    
    // Add location-specific variations for local SEO
    optimizedContent = this.enhanceWithLocalSeo(optimizedContent, platform);
    
    // Incorporate trending automation industry keywords
    optimizedContent = this.addTrendingKeywords(optimizedContent, platform);

    return optimizedContent;
  }

  /**
   * Generate SEO-optimized meta tags for pages
   */
  public generateMetaTags(pageType: string, targetKeyword: string): {
    title: string;
    description: string;
    keywords: string;
  } {
    if (!this.seoConfig) {
      return {
        title: "TheAgencyIQ - Queensland Business Automation",
        description: "Transform your Queensland business with intelligent automation solutions",
        keywords: "business automation, Queensland, SME, AI"
      };
    }

    const config = this.seoConfig.config;
    
    // Select appropriate title template
    const titleTemplate = config.contentOptimization.titleTemplates[
      Math.floor(Math.random() * config.contentOptimization.titleTemplates.length)
    ];
    
    // Select appropriate meta description template
    const descTemplate = config.contentOptimization.metaDescriptionTemplates[
      Math.floor(Math.random() * config.contentOptimization.metaDescriptionTemplates.length)
    ];

    const title = titleTemplate.replace('{{keyword}}', targetKeyword);
    const description = descTemplate.replace('{{keyword}}', targetKeyword);
    
    // Combine relevant keywords
    const keywords = [
      ...config.seoStrategy.primaryKeywords.slice(0, 5),
      ...config.seoStrategy.localSeoKeywords.slice(0, 3),
      targetKeyword
    ].join(', ');

    return { title, description, keywords };
  }

  /**
   * Get content suggestions based on Queensland market trends
   */
  public getQueenslandMarketContentSuggestions(): {
    blogTopics: string[];
    socialMediaTopics: string[];
    landingPageFocus: string[];
  } {
    if (!this.seoConfig) {
      return {
        blogTopics: [],
        socialMediaTopics: [],
        landingPageFocus: []
      };
    }

    const config = this.seoConfig.config;

    return {
      blogTopics: config.contentStrategy.blogTopics,
      socialMediaTopics: [
        "Queensland SME Success Stories",
        "Brisbane Business Automation Tips",
        "Gold Coast Entrepreneur Spotlight",
        "Queensland Digital Transformation",
        "AI Tools for Australian Businesses"
      ],
      landingPageFocus: config.contentStrategy.landingPageFocus
    };
  }

  /**
   * Select optimal keywords based on platform and content type
   */
  private selectOptimalKeywords(platform: string, targetKeyword?: string): string[] {
    if (!this.seoConfig) return [];

    const config = this.seoConfig.config;
    let keywords: string[] = [];

    // Platform-specific keyword selection
    switch (platform.toLowerCase()) {
      case 'facebook':
        keywords = [
          ...config.seoStrategy.localSeoKeywords.slice(0, 2),
          ...config.seoStrategy.primaryKeywords.slice(0, 2)
        ];
        break;
      case 'linkedin':
        keywords = [
          ...config.seoStrategy.industrySpecificKeywords.slice(0, 2),
          ...config.seoStrategy.competitorKeywords.slice(0, 1)
        ];
        break;
      case 'instagram':
        keywords = [
          ...config.seoStrategy.trendingKeywords.slice(0, 2),
          ...config.seoStrategy.localSeoKeywords.slice(0, 1)
        ];
        break;
      case 'x':
      case 'twitter':
        keywords = [
          ...config.seoStrategy.primaryKeywords.slice(0, 1),
          ...config.seoStrategy.trendingKeywords.slice(0, 1)
        ];
        break;
      case 'youtube':
        keywords = [
          ...config.seoStrategy.longTailKeywords.slice(0, 1),
          ...config.seoStrategy.localSeoKeywords.slice(0, 1)
        ];
        break;
      default:
        keywords = config.seoStrategy.primaryKeywords.slice(0, 3);
    }

    // Add target keyword if provided
    if (targetKeyword) {
      keywords.unshift(targetKeyword);
    }

    return keywords;
  }

  /**
   * Integrate Queensland-specific market terms naturally into content
   */
  private integrateQueenslandMarketTerms(content: string, platform: string): string {
    if (!this.seoConfig) return content;

    const queenslandTerms = [
      'Queensland entrepreneurs',
      'Brisbane business owners', 
      'Gold Coast SMEs',
      'Sunshine Coast businesses',
      'Queensland market',
      'Australian SMEs'
    ];

    // Randomly select and integrate 1-2 terms based on platform constraints
    const termsToAdd = platform === 'x' ? 1 : 2;
    const selectedTerms = queenslandTerms.slice(0, termsToAdd);

    let enhancedContent = content;
    
    // Integrate terms naturally without disrupting the message
    selectedTerms.forEach(term => {
      if (!enhancedContent.includes(term) && enhancedContent.length + term.length < 280) {
        // For X platform, be more careful about character limits
        if (platform === 'x' && enhancedContent.length + term.length > 250) {
          return;
        }
        
        // Add term in a natural way
        enhancedContent = enhancedContent.replace(
          'business owners',
          term
        ).replace(
          'entrepreneurs',
          'Queensland entrepreneurs'
        ).replace(
          'SMEs',
          'Queensland SMEs'
        );
      }
    });

    return enhancedContent;
  }

  /**
   * Enhance content with local SEO elements
   */
  private enhanceWithLocalSeo(content: string, platform: string): string {
    if (!this.seoConfig) return content;

    const config = this.seoConfig.config;
    const localVariations = config.localSeoOptimization.localContent.localKeywordVariations;
    
    // Add "in Queensland" or "across Brisbane" naturally
    if (platform !== 'x' && !content.includes('Queensland') && !content.includes('Brisbane')) {
      const variation = localVariations[Math.floor(Math.random() * localVariations.length)];
      
      // Insert location naturally
      if (content.includes('businesses') && !content.includes('Queensland')) {
        content = content.replace('businesses', `businesses ${variation}`);
      }
    }

    return content;
  }

  /**
   * Add trending automation keywords to improve discoverability
   */
  private addTrendingKeywords(content: string, platform: string): string {
    if (!this.seoConfig) return content;

    const config = this.seoConfig.config;
    const trendingKeywords = config.seoStrategy.trendingKeywords;

    // For platforms with more character space, add trending terms
    if (platform !== 'x' && platform !== 'instagram') {
      const trendingTerm = trendingKeywords[Math.floor(Math.random() * trendingKeywords.length)];
      
      // Add trending term if not already present and if there's space
      if (!content.toLowerCase().includes(trendingTerm.toLowerCase())) {
        // Add as a natural extension
        if (content.includes('automation') && !content.includes('2025')) {
          content = content.replace('automation', 'intelligent automation');
        }
      }
    }

    return content;
  }

  /**
   * Get location-specific content recommendations
   */
  public getLocationSpecificContent(): {
    serviceAreas: string[];
    locationPages: string[];
    businessCategories: string[];
  } {
    if (!this.seoConfig) {
      return {
        serviceAreas: [],
        locationPages: [],
        businessCategories: []
      };
    }

    const config = this.seoConfig.config;

    return {
      serviceAreas: config.serviceArea,
      locationPages: config.localSeoOptimization.localContent.locationPages,
      businessCategories: config.localSeoOptimization.businessListings.categories
    };
  }

  /**
   * Generate voice search optimized content
   */
  public optimizeForVoiceSearch(content: string): string {
    if (!this.seoConfig) return content;

    const config = this.seoConfig.config;
    const voiceKeywords = config.voiceSearchOptimization.conversationalKeywords;

    // Make content more conversational for voice search
    let optimizedContent = content;

    // Add question-based phrases that align with voice search
    if (content.includes('automation') && !content.includes('how to')) {
      const voicePhrase = voiceKeywords[Math.floor(Math.random() * voiceKeywords.length)];
      
      // Integrate voice-friendly phrases naturally
      if (optimizedContent.length + 20 < 280) { // Ensure X compatibility
        optimizedContent = optimizedContent.replace(
          'business automation',
          'business automation solutions'
        );
      }
    }

    return optimizedContent;
  }
}

// Export singleton instance
export const seoOptimizationService = new SeoOptimizationService();
export default SeoOptimizationService;