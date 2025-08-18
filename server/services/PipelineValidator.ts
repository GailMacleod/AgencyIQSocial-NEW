export class PipelineValidator {
  // Validate JTBD input to prevent junk from causing generation failures
  static validateJTBDInput(jtbdData: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (!jtbdData) {
      errors.push('JTBD data is required');
      return { isValid: false, errors };
    }

    // Core JTBD validation with regex
    const coreJobRegex = /^[a-zA-Z0-9\s\-,.!?'"()]{10,200}$/;
    if (!jtbdData.coreJob || !coreJobRegex.test(jtbdData.coreJob)) {
      errors.push('Core job must be 10-200 characters, alphanumeric with basic punctuation');
    }

    // Pain point validation
    const painPointRegex = /^[a-zA-Z0-9\s\-,.!?'"()]{5,150}$/;
    if (!jtbdData.painPoint || !painPointRegex.test(jtbdData.painPoint)) {
      errors.push('Pain point must be 5-150 characters, alphanumeric with basic punctuation');
    }

    // Desired state validation
    const desiredStateRegex = /^[a-zA-Z0-9\s\-,.!?'"()]{5,150}$/;
    if (!jtbdData.desiredState || !desiredStateRegex.test(jtbdData.desiredState)) {
      errors.push('Desired state must be 5-150 characters, alphanumeric with basic punctuation');
    }

    // Emotional outcome validation
    const emotionalOutcomeRegex = /^[a-zA-Z\s\-]{3,50}$/;
    if (!jtbdData.emotionalOutcome || !emotionalOutcomeRegex.test(jtbdData.emotionalOutcome)) {
      errors.push('Emotional outcome must be 3-50 characters, letters and spaces only');
    }

    // Queensland context validation (optional but recommended)
    if (jtbdData.qldContext) {
      const qldContextRegex = /^[a-zA-Z0-9\s\-,.!?'"()]{5,100}$/;
      if (!qldContextRegex.test(jtbdData.qldContext)) {
        errors.push('Queensland context must be 5-100 characters, alphanumeric with basic punctuation');
      }
    }

    return { isValid: errors.length === 0, errors };
  }

  // Validate brand purpose for waterfall
  static validateBrandPurpose(brandPurpose: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!brandPurpose) {
      errors.push('Brand purpose data is required');
      return { isValid: false, errors };
    }

    // Business name validation
    const nameRegex = /^[a-zA-Z0-9\s\-&.]{2,100}$/;
    if (!brandPurpose.businessName || !nameRegex.test(brandPurpose.businessName)) {
      errors.push('Business name must be 2-100 characters, alphanumeric with basic symbols');
    }

    // Industry validation
    const industryRegex = /^[a-zA-Z\s\-&]{2,50}$/;
    if (!brandPurpose.industry || !industryRegex.test(brandPurpose.industry)) {
      errors.push('Industry must be 2-50 characters, letters and spaces only');
    }

    // Target audience validation
    const audienceRegex = /^[a-zA-Z0-9\s\-,.!?'"()]{5,200}$/;
    if (!brandPurpose.targetAudience || !audienceRegex.test(brandPurpose.targetAudience)) {
      errors.push('Target audience must be 5-200 characters, alphanumeric with basic punctuation');
    }

    // Core purpose validation
    const purposeRegex = /^[a-zA-Z0-9\s\-,.!?'"()]{10,300}$/;
    if (!brandPurpose.corePurpose || !purposeRegex.test(brandPurpose.corePurpose)) {
      errors.push('Core purpose must be 10-300 characters, alphanumeric with basic punctuation');
    }

    return { isValid: errors.length === 0, errors };
  }

  // Validate prompt before sending to Veo3 to prevent API failures
  static validateVideoPrompt(prompt: string): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!prompt || typeof prompt !== 'string') {
      errors.push('Prompt must be a non-empty string');
      return { isValid: false, errors };
    }

    // Length validation for Veo3
    if (prompt.length < 20) {
      errors.push('Prompt too short - minimum 20 characters for quality generation');
    }

    if (prompt.length > 2000) {
      errors.push('Prompt too long - maximum 2000 characters for Veo3 API');
    }

    // Content safety checks
    const unsafePatterns = [
      /explicit/i, /violence/i, /illegal/i, /harmful/i, /adult/i,
      /sexual/i, /drug/i, /weapon/i, /hate/i, /terror/i
    ];

    for (const pattern of unsafePatterns) {
      if (pattern.test(prompt)) {
        errors.push('Prompt contains potentially unsafe content');
        break;
      }
    }

    // Technical format validation
    const invalidChars = /[<>{}[\]\\|`~]/;
    if (invalidChars.test(prompt)) {
      errors.push('Prompt contains invalid characters that may cause API errors');
    }

    // Ensure business context (not just random text)
    const businessKeywords = [
      'business', 'queensland', 'sme', 'professional', 'service', 'customer',
      'growth', 'automation', 'efficiency', 'success', 'transform'
    ];

    const hasBusinessContext = businessKeywords.some(keyword => 
      prompt.toLowerCase().includes(keyword)
    );

    if (!hasBusinessContext) {
      errors.push('Prompt should include business-relevant context for better results');
    }

    return { isValid: errors.length === 0, errors };
  }

  // Retry logic for timeout scenarios
  static async retryWithBackoff<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    baseDelay: number = 1000
  ): Promise<T> {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error: any) {
        const isTimeout = error.message?.includes('timeout') || 
                         error.message?.includes('ETIMEDOUT') ||
                         error.code === 'ECONNRESET';

        if (isTimeout && attempt < maxRetries - 1) {
          const delay = baseDelay * Math.pow(2, attempt);
          console.log(`⏱️ Timeout detected, retrying in ${delay}ms... (attempt ${attempt + 1}/${maxRetries})`);
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }

        throw error;
      }
    }

    throw new Error('Maximum retries exceeded');
  }

  // Comprehensive waterfall validation
  static async validateStrategyzerWaterfall(waterfallData: any): Promise<{ isValid: boolean; errors: string[] }> {
    const errors: string[] = [];

    // Phase 1: Brand Purpose
    const brandValidation = this.validateBrandPurpose(waterfallData.brandPurpose);
    if (!brandValidation.isValid) {
      errors.push(...brandValidation.errors.map(e => `Brand Purpose: ${e}`));
    }

    // Phase 2: JTBD Analysis
    const jtbdValidation = this.validateJTBDInput(waterfallData.jtbdAnalysis);
    if (!jtbdValidation.isValid) {
      errors.push(...jtbdValidation.errors.map(e => `JTBD Analysis: ${e}`));
    }

    // Phase 3: Queensland Context
    if (waterfallData.qldContext) {
      const qldRegex = /^[a-zA-Z0-9\s\-,.!?'"()]{10,200}$/;
      if (!qldRegex.test(waterfallData.qldContext)) {
        errors.push('Queensland Context: Must be 10-200 characters with valid formatting');
      }
    }

    // Phase 4: Platform Alignment
    const validPlatforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
    if (!waterfallData.platform || !validPlatforms.includes(waterfallData.platform)) {
      errors.push(`Platform: Must be one of ${validPlatforms.join(', ')}`);
    }

    // Phase 5: Content Strategy
    if (waterfallData.contentStrategy) {
      const strategyRegex = /^[a-zA-Z0-9\s\-,.!?'"()]{20,500}$/;
      if (!strategyRegex.test(waterfallData.contentStrategy)) {
        errors.push('Content Strategy: Must be 20-500 characters with valid formatting');
      }
    }

    return { isValid: errors.length === 0, errors };
  }

  // Generate enhanced prompts from validated waterfall data
  static generateEnhancedPrompt(validatedData: any): string {
    const { brandPurpose, jtbdAnalysis, qldContext, platform } = validatedData;

    const prompt = `
Create cinematic ${platform} video showcasing Queensland business transformation:

BUSINESS CONTEXT:
- Company: ${brandPurpose.businessName}
- Industry: ${brandPurpose.industry}
- Purpose: ${brandPurpose.corePurpose}

JTBD TRANSFORMATION:
- Core Job: ${jtbdAnalysis.coreJob}
- Pain Point: ${jtbdAnalysis.painPoint}
- Desired State: ${jtbdAnalysis.desiredState}
- Emotional Outcome: ${jtbdAnalysis.emotionalOutcome}

QUEENSLAND ELEMENTS:
${qldContext || 'Authentic Queensland business environment with local context'}

VISUAL STYLE:
- Professional cinematography with dynamic camera movements
- Queensland business settings (modern offices, local environments)
- Transformation journey from challenge to success
- Authentic Australian business culture
- 8-second duration, 16:9 aspect ratio
- High-quality production values

Show the journey from "${jtbdAnalysis.painPoint}" to "${jtbdAnalysis.desiredState}" with compelling visual storytelling that resonates with Queensland SME audiences.
    `.trim();

    return prompt;
  }
}