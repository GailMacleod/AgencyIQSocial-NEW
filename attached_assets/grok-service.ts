// grok-service.ts
import axios from 'axios';

export default {
  async generateContent(prompt: string) {
    const response = await axios.post('https://api.x.ai/v1/grok', { prompt }, {
      headers: { Authorization: `Bearer ${process.env.XAI_API_KEY}` }
    });
    return response.data.content;
  },
};