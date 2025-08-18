class PipelineValidator {
  static validateVideoPrompt(prompt) {
    if (!prompt || typeof prompt !== 'string') {
      return {
        isValid: false,
        errors: ['Prompt is required and must be a string']
      };
    }

    // Simple validation - allow most prompts through
    if (prompt.length > 1500) {
      return {
        isValid: false,
        errors: ['Prompt too long - maximum 1500 characters for Veo3 API']
      };
    }

    // Basic content validation
    const forbiddenWords = ['explicit', 'violent', 'illegal'];
    const hasUnsafeContent = forbiddenWords.some(word => 
      prompt.toLowerCase().includes(word)
    );

    if (hasUnsafeContent) {
      return {
        isValid: false,
        errors: ['Prompt contains potentially unsafe content']
      };
    }

    return {
      isValid: true,
      errors: []
    };
  }
}

module.exports = { PipelineValidator };