import axios from 'axios';
import { toast } from 'react-toastify';

export async function apiRequest(url: string, options: RequestInit = {}) {
  try {
    const response = await fetch(url, options);
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    return response.json();
  } catch (error: unknown) {
    console.error('API request failed:', (error as Error).message);
    toast.error('API request failed');
    throw error;
  }
}