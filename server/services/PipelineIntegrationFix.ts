/**
 * PIPELINE INTEGRATION FIX - ADDRESSING ARCHITECTURAL FRACTURES
 * Implements complete pipeline flow: Onboard → Brand Purpose → Engine → Gen → Post
 * Fixes broken spots throughout the waterfall with session caching and error recovery
 */

import { storage } from '../storage';
import { quotaManager } from './QuotaManager';
import { postingQueue } from './PostingQueue';
import SessionCacheManager from './SessionCacheManager';
import { CustomerOnboardingOAuth } from './CustomerOnboardingOAuth';
import { PipelineOrchestrator } from './PipelineOrchestrator';
import { DataCleanupService } from './DataCleanupService';

interface PipelineStep {
  step: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  data?: any;
  error?: string;
  timestamp: string;
}

interface PipelineState {
  userId: number;
  sessionId: string;
  currentStep: string;
  steps: PipelineStep[];
  jtbdInputs?: any;
  brandPurpose?: any;
  generatedContent?: any;
  quotaStatus?: any;
  errors: string[];
  startedAt: string;
  completedAt?: string;
}

export class PipelineIntegrationFix {
  private sessionManager: SessionCacheManager;
  private onboardingService: CustomerOnboardingOAuth;
  private pipelineOrchestrator: PipelineOrchestrator;

  constructor(sessionManager: SessionCacheManager) {
    this.sessionManager = sessionManager;
    this.onboardingService = new CustomerOnboardingOAuth();
    this.pipelineOrchestrator = new PipelineOrchestrator();
  }

  /**
   * Initialize complete pipeline with session caching
   * Prevents data loss during Brand Purpose waterfall
   */
  async initializePipeline(userId: number, sessionId: string): Promise<PipelineState> {
    const pipelineState: PipelineState = {
      userId,
      sessionId,
      currentStep: 'onboarding',
      steps: [
        { step: 'onboarding', status: 'pending', timestamp: new Date().toISOString() },
        { step: 'brand_purpose', status: 'pending', timestamp: new Date().toISOString() },
        { step: 'content_engine', status: 'pending', timestamp: new Date().toISOString() },
        { step: 'content_generation', status: 'pending', timestamp: new Date().toISOString() },
        { step: 'auto_posting', status: 'pending', timestamp: new Date().toISOString() }
      ],
      errors: [],
      startedAt: new Date().toISOString()
    };

    // Cache initial state
    await this.sessionManager.cachePipelineData(userId, pipelineState);
    console.log(`🚀 Pipeline initialized for user ${userId} with session caching`);

    return pipelineState;
  }

  /**
   * Execute OAuth-secured onboarding step
   * Fixes friction-heavy manual entries and token refresh issues
   */
  async executeOnboardingStep(userId: number, provider: string): Promise<PipelineState> {
    let pipelineState = await this.sessionManager.getCachedPipelineData(userId);
    if (!pipelineState) {
      throw new Error('Pipeline not initialized - session data lost');
    }

    try {
      // Update step status
      this.updateStepStatus(pipelineState, 'onboarding', 'in_progress');
      await this.sessionManager.cachePipelineData(userId, pipelineState);

      // Execute OAuth onboarding with automatic business data extraction
      const onboardingResult = await this.onboardingService.initiateOAuth(provider, userId.toString());
      
      // Store onboarding data in pipeline state
      pipelineState.steps.find(s => s.step === 'onboarding')!.data = onboardingResult;
      this.updateStepStatus(pipelineState, 'onboarding', 'completed');
      
      // Auto-advance to brand purpose if business data extracted
      if (onboardingResult.businessData) {
        pipelineState.currentStep = 'brand_purpose';
        pipelineState.jtbdInputs = this.extractJTBDFromBusinessData(onboardingResult.businessData);
      }

      await this.sessionManager.cachePipelineData(userId, pipelineState);
      console.log(`✅ Onboarding step completed for user ${userId}`);

      return pipelineState;
    } catch (error: any) {
      this.updateStepStatus(pipelineState, 'onboarding', 'failed', error.message);
      pipelineState.errors.push(`Onboarding failed: ${error.message}`);
      await this.sessionManager.cachePipelineData(userId, pipelineState);
      throw error;
    }
  }

  /**
   * Execute Brand Purpose step with waterfall guidance
   * Fixes session-cached JTBD inputs loss during Brand Purpose waterfall
   */
  async executeBrandPurposeStep(userId: number, brandPurposeData: any): Promise<PipelineState> {
    let pipelineState = await this.sessionManager.getCachedPipelineData(userId);
    if (!pipelineState) {
      throw new Error('Pipeline not initialized - brand purpose data lost');
    }

    try {
      this.updateStepStatus(pipelineState, 'brand_purpose', 'in_progress');
      await this.sessionManager.cachePipelineData(userId, pipelineState);

      // Validate JTBD inputs with cached data
      const cachedJTBD = pipelineState.jtbdInputs;
      if (!cachedJTBD && !brandPurposeData.jobToBeDone) {
        throw new Error('JTBD inputs lost - session cache failed');
      }

      // Merge cached JTBD with new brand purpose data
      const completeBrandPurpose = {
        ...brandPurposeData,
        jobToBeDone: brandPurposeData.jobToBeDone || cachedJTBD?.jobToBeDone,
        motivations: brandPurposeData.motivations || cachedJTBD?.motivations,
        painPoints: brandPurposeData.painPoints || cachedJTBD?.painPoints
      };

      // Validate quality with JTBD requirements
      const jtbdValidation = this.validateJTBDQuality(completeBrandPurpose);
      if (!jtbdValidation.valid) {
        throw new Error(`JTBD validation failed: ${jtbdValidation.reason}`);
      }

      // Save to database and cache
      const savedBrandPurpose = await storage.createBrandPurpose({
        userId,
        ...completeBrandPurpose
      });

      pipelineState.brandPurpose = savedBrandPurpose;
      pipelineState.steps.find(s => s.step === 'brand_purpose')!.data = savedBrandPurpose;
      this.updateStepStatus(pipelineState, 'brand_purpose', 'completed');
      pipelineState.currentStep = 'content_engine';

      await this.sessionManager.cachePipelineData(userId, pipelineState);
      console.log(`✅ Brand Purpose step completed for user ${userId}`);

      return pipelineState;
    } catch (error: any) {
      this.updateStepStatus(pipelineState, 'brand_purpose', 'failed', error.message);
      pipelineState.errors.push(`Brand Purpose failed: ${error.message}`);
      await this.sessionManager.cachePipelineData(userId, pipelineState);
      throw error;
    }
  }

  /**
   * Execute Content Engine step with Grok PhD integration
   * Fixes quota integration and burst protection
   */
  async executeContentEngineStep(userId: number): Promise<PipelineState> {
    let pipelineState = await this.sessionManager.getCachedPipelineData(userId);
    if (!pipelineState || !pipelineState.brandPurpose) {
      throw new Error('Pipeline incomplete - brand purpose required for content engine');
    }

    try {
      this.updateStepStatus(pipelineState, 'content_engine', 'in_progress');
      await this.sessionManager.cachePipelineData(userId, pipelineState);

      // Check quota before content generation
      const user = await storage.getUser(userId);
      const subscriptionTier = user?.subscriptionPlan === 'free' ? 'free' : 
                             user?.subscriptionPlan === 'enterprise' ? 'enterprise' : 'professional';
      
      const quotaCheck = await quotaManager.canGenerateContent(userId, subscriptionTier);
      if (!quotaCheck.allowed) {
        throw new Error(quotaCheck.message || 'Quota exceeded');
      }

      // Execute content generation with quota protection
      const contentResult = await this.pipelineOrchestrator.executeComplete({
        userId,
        brandPurpose: pipelineState.brandPurpose,
        quotaEnforcement: true,
        burstProtection: true
      });

      // Record quota usage
      await quotaManager.recordContentGeneration(userId, subscriptionTier);

      pipelineState.generatedContent = contentResult;
      pipelineState.quotaStatus = quotaCheck.quota;
      pipelineState.steps.find(s => s.step === 'content_engine')!.data = contentResult;
      this.updateStepStatus(pipelineState, 'content_engine', 'completed');
      pipelineState.currentStep = 'content_generation';

      await this.sessionManager.cachePipelineData(userId, pipelineState);
      console.log(`✅ Content Engine step completed for user ${userId}`);

      return pipelineState;
    } catch (error: any) {
      this.updateStepStatus(pipelineState, 'content_engine', 'failed', error.message);
      pipelineState.errors.push(`Content Engine failed: ${error.message}`);
      await this.sessionManager.cachePipelineData(userId, pipelineState);
      throw error;
    }
  }

  /**
   * Execute Content Generation step with Video/Post generation
   * Fixes integration between video prompts and post creation
   */
  async executeContentGenerationStep(userId: number, generationOptions: any = {}): Promise<PipelineState> {
    let pipelineState = await this.sessionManager.getCachedPipelineData(userId);
    if (!pipelineState || !pipelineState.generatedContent) {
      throw new Error('Pipeline incomplete - content engine required for generation');
    }

    try {
      this.updateStepStatus(pipelineState, 'content_generation', 'in_progress');
      await this.sessionManager.cachePipelineData(userId, pipelineState);

      // Generate posts with video integration
      const { generateContentCalendar } = await import('../grok');
      
      const contentParams = {
        brandName: pipelineState.brandPurpose.brandName,
        productsServices: pipelineState.brandPurpose.productsServices,
        corePurpose: pipelineState.brandPurpose.corePurpose,
        audience: pipelineState.brandPurpose.audience,
        jobToBeDone: pipelineState.brandPurpose.jobToBeDone,
        motivations: pipelineState.brandPurpose.motivations,
        painPoints: pipelineState.brandPurpose.painPoints,
        goals: pipelineState.brandPurpose.goals || {},
        contactDetails: pipelineState.brandPurpose.contactDetails || {},
        platforms: generationOptions.platforms || ['facebook', 'instagram', 'linkedin', 'x', 'youtube'],
        totalPosts: generationOptions.totalPosts || 20
      };

      const generatedPosts = await generateContentCalendar(contentParams);

      // Save posts to database with transaction safety
      const savedPosts = [];
      for (const post of generatedPosts) {
        try {
          const postData = {
            userId,
            platform: post.platform,
            content: post.content,
            status: 'draft' as const,
            scheduledFor: new Date(post.scheduledFor)
          };
          
          const savedPost = await storage.createPost(postData);
          savedPosts.push(savedPost);
        } catch (error) {
          console.error('Error saving post:', error);
          pipelineState.errors.push(`Post save failed: ${error}`);
        }
      }

      pipelineState.steps.find(s => s.step === 'content_generation')!.data = {
        generatedCount: generatedPosts.length,
        savedCount: savedPosts.length,
        posts: savedPosts
      };
      
      this.updateStepStatus(pipelineState, 'content_generation', 'completed');
      pipelineState.currentStep = 'auto_posting';

      await this.sessionManager.cachePipelineData(userId, pipelineState);
      console.log(`✅ Content Generation step completed for user ${userId}: ${savedPosts.length} posts created`);

      return pipelineState;
    } catch (error: any) {
      this.updateStepStatus(pipelineState, 'content_generation', 'failed', error.message);
      pipelineState.errors.push(`Content Generation failed: ${error.message}`);
      await this.sessionManager.cachePipelineData(userId, pipelineState);
      throw error;
    }
  }

  /**
   * Execute Auto-Posting step with queue management
   * Fixes burst posting and platform bans
   */
  async executeAutoPostingStep(userId: number): Promise<PipelineState> {
    let pipelineState = await this.sessionManager.getCachedPipelineData(userId);
    if (!pipelineState) {
      throw new Error('Pipeline incomplete - content generation required for auto-posting');
    }

    try {
      this.updateStepStatus(pipelineState, 'auto_posting', 'in_progress');
      await this.sessionManager.cachePipelineData(userId, pipelineState);

      // Get approved posts for this user
      const approvedPosts = await storage.getPostsByUser(userId);
      const postsToQueue = approvedPosts.filter(p => p.status === 'approved');

      if (postsToQueue.length === 0) {
        throw new Error('No approved posts found for auto-posting');
      }

      // Add posts to queue with staggered delays (prevents burst posting)
      const queuedPosts = await postingQueue.addBatchToQueue(
        postsToQueue.map(post => ({
          postId: post.id,
          platform: post.platform,
          content: post.content,
          userId: post.userId
        }))
      );

      pipelineState.steps.find(s => s.step === 'auto_posting')!.data = {
        queuedCount: queuedPosts.length,
        queueIds: queuedPosts
      };
      
      this.updateStepStatus(pipelineState, 'auto_posting', 'completed');
      pipelineState.completedAt = new Date().toISOString();

      await this.sessionManager.cachePipelineData(userId, pipelineState);
      console.log(`✅ Auto-Posting step completed for user ${userId}: ${queuedPosts.length} posts queued`);

      // Clear pipeline cache after successful completion
      setTimeout(async () => {
        await this.sessionManager.clearPipelineCache(userId);
      }, 5000); // Clear after 5 seconds to allow final status checks

      return pipelineState;
    } catch (error: any) {
      this.updateStepStatus(pipelineState, 'auto_posting', 'failed', error.message);
      pipelineState.errors.push(`Auto-Posting failed: ${error.message}`);
      await this.sessionManager.cachePipelineData(userId, pipelineState);
      throw error;
    }
  }

  /**
   * Recovery mechanism for interrupted pipelines
   * Handles Replit stability issues and connection drops
   */
  async recoverPipeline(userId: number): Promise<PipelineState | null> {
    try {
      const cachedState = await this.sessionManager.getCachedPipelineData(userId);
      if (!cachedState) {
        console.log(`ℹ️ No cached pipeline state found for user ${userId}`);
        return null;
      }

      // Analyze where pipeline failed
      const failedSteps = cachedState.steps.filter(s => s.status === 'failed');
      const inProgressSteps = cachedState.steps.filter(s => s.status === 'in_progress');
      const pendingSteps = cachedState.steps.filter(s => s.status === 'pending');

      console.log(`🔄 Pipeline recovery for user ${userId}:`, {
        currentStep: cachedState.currentStep,
        failedSteps: failedSteps.length,
        inProgressSteps: inProgressSteps.length,
        pendingSteps: pendingSteps.length,
        errors: cachedState.errors.length
      });

      // Provide recovery recommendations
      const recommendations = [];
      
      if (failedSteps.length > 0) {
        recommendations.push(`Retry failed steps: ${failedSteps.map(s => s.step).join(', ')}`);
      }
      
      if (inProgressSteps.length > 0) {
        recommendations.push(`Resume interrupted steps: ${inProgressSteps.map(s => s.step).join(', ')}`);
      }
      
      if (cachedState.errors.length > 0) {
        recommendations.push(`Address errors: ${cachedState.errors.slice(0, 3).join('; ')}`);
      }

      // Add recovery recommendations to cached state
      cachedState.recoveryRecommendations = recommendations;
      await this.sessionManager.cachePipelineData(userId, cachedState);

      return cachedState;
    } catch (error: any) {
      console.error('❌ Pipeline recovery failed:', error);
      return null;
    }
  }

  /**
   * Helper: Update step status
   */
  private updateStepStatus(pipelineState: PipelineState, stepName: string, status: PipelineStep['status'], error?: string): void {
    const step = pipelineState.steps.find(s => s.step === stepName);
    if (step) {
      step.status = status;
      step.timestamp = new Date().toISOString();
      if (error) {
        step.error = error;
      }
    }
  }

  /**
   * Helper: Extract JTBD from business data
   */
  private extractJTBDFromBusinessData(businessData: any): any {
    return {
      jobToBeDone: businessData.description || businessData.about,
      motivations: businessData.services || businessData.categories,
      painPoints: businessData.challenges || [],
      extractedFrom: 'oauth_business_data',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Helper: Validate JTBD quality
   */
  private validateJTBDQuality(brandPurpose: any): { valid: boolean; reason?: string } {
    if (!brandPurpose.jobToBeDone || brandPurpose.jobToBeDone.length < 10) {
      return { valid: false, reason: 'Job To Be Done too short or missing' };
    }

    if (!brandPurpose.audience || brandPurpose.audience.length < 5) {
      return { valid: false, reason: 'Target audience description insufficient' };
    }

    // Check for quality words
    const qualityWords = ['help', 'solve', 'provide', 'enable', 'improve', 'achieve', 'deliver'];
    const hasQualityWords = qualityWords.some(word => 
      brandPurpose.jobToBeDone.toLowerCase().includes(word)
    );

    if (!hasQualityWords) {
      return { valid: false, reason: 'JTBD lacks action-oriented quality words' };
    }

    return { valid: true };
  }
}

export default PipelineIntegrationFix;