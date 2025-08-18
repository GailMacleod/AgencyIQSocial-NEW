// grok-service.ts
import axios from 'axios';

async function generateContent(prompt: string) {
  try {
    const response = await axios.post('https://api.x.ai/v1/chat/completions', {
      model: 'grok-beta', // Or latest 2025 model
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { Authorization: `Bearer ${process.env.XAI_API_KEY}` }
    });
    return response.data.choices[0].message.content;
  } catch (error) {
    console.error(`Grok generation failed: ${error.message}`);
    throw error;
  }
}

export { generateContent };