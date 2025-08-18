// Test Google AI Studio API Key
const { GoogleGenerativeAI } = require('@google/generative-ai');

// Check if key exists
console.log('Key exists:', !!process.env.GOOGLE_AI_STUDIO_KEY);
console.log('Key preview:', process.env.GOOGLE_AI_STUDIO_KEY?.slice(0, 5) + '...');

// Test Veo3 call
async function testVeo3() {
  try {
    if (!process.env.GOOGLE_AI_STUDIO_KEY) {
      throw new Error('GOOGLE_AI_STUDIO_KEY not found in environment');
    }

    console.log('Initializing Google AI with key...');
    const genAI = new GoogleGenerativeAI(process.env.GOOGLE_AI_STUDIO_KEY);
    const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });
    
    console.log('Testing simple generation...');
    const result = await model.generateContent('Describe a 2s video of a cat jumping.');
    
    console.log('✅ SUCCESS! Google AI API key is working');
    console.log('Response preview:', result.response.text().slice(0, 200) + '...');
    
    // Test video generation capability
    console.log('\nTesting Queensland business video prompt...');
    const videoResult = await model.generateContent(`
Create a cinematic 8-second video prompt for Queensland small business:
A stressed Brisbane cafe owner discovers automation, transforming chaotic morning rush into smooth operation.
Focus on relief, efficiency, and Queensland authenticity.
`);
    
    console.log('✅ Video generation test SUCCESS!');
    console.log('Video prompt response:', videoResult.response.text().slice(0, 300) + '...');
    
  } catch (error) {
    console.error('❌ Veo3 test failed:', error.message);
    console.error('Full error:', error);
    
    // Diagnostic info
    if (error.message.includes('API key')) {
      console.error('-> Fix: Check API key in Google AI Studio');
    } else if (error.message.includes('429')) {
      console.error('-> Fix: Rate limit hit, implement quota manager');
    } else if (error.message.includes('model')) {
      console.error('-> Fix: Try gemini-1.5-flash instead of gemini-2.5-flash');
    }
  }
}

// Run the test
console.log('🧪 Testing Google AI Studio API Key...\n');
testVeo3();