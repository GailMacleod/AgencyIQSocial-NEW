import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { MessageCircleIcon, XIcon, SendIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { apiRequest } from "@/lib/api";

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

export default function AIWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: '1',
      role: 'assistant',
      content: 'Hi! I\'m your strategic AI assistant with comprehensive knowledge of TheAgencyIQ platform and deep expertise in Queensland SME success.\n\nI can provide expert guidance on:\n• Complete platform functionality & features\n• Strategic planning & brand positioning\n• Content creation & social media strategy\n• Platform optimisation (Facebook, Instagram, LinkedIn, X, YouTube)\n• Subscription management & billing\n• Analytics & performance monitoring\n• Technical troubleshooting & support\n• Business growth & customer acquisition\n• Local Queensland market insights\n\nI understand how every feature works together - from brand purpose setup to multi-platform publishing. What specific question can I help you with?',
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');

  const sendMessageMutation = useMutation({
    mutationFn: async (query: string) => {
      try {
        const response = await apiRequest("POST", "/api/ai-query", { query });
        return await response.json();
      } catch (error) {
        console.error('AI query error:', error);
        throw error;
      }
    },
    onSuccess: (data) => {
      const assistantMessage: ChatMessage = {
        id: Date.now().toString(),
        role: 'assistant',
        content: data.response || 'I received your message but had trouble generating a response. Please try again.',
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, assistantMessage]);
    },
    onError: (error) => {
      console.error('AI query error:', error);
      const errorMessage: ChatMessage = {
        id: Date.now().toString(),
        role: 'assistant', 
        content: 'Sorry, I encountered an error. Please try again.',
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errorMessage]);
    },
  });

  const handleSendMessage = () => {
    if (!input.trim()) return;

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      role: 'user',
      content: input,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    sendMessageMutation.mutate(input);
    setInput('');
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  return (
    <>
      {/* Widget Button */}
      <div className="fixed bottom-6 right-6 z-50">
        <Button
          onClick={() => setIsOpen(!isOpen)}
          className="w-12 h-12 rounded-full flex items-center justify-center text-white hover:opacity-80 transition-all duration-200 shadow-lg grok-widget-entrance"
          style={{ backgroundColor: '#915fd7' }}
        >
          <MessageCircleIcon className="w-6 h-6" />
        </Button>
      </div>

      {/* Chat Window */}
      {isOpen && (
        <div className="fixed bottom-20 right-6 z-50 w-80">
          <Card className="card-agencyiq">
            <CardHeader className="bg-accent text-white p-4 rounded-t-lg flex flex-row justify-between items-center">
              <h4 className="font-medium">Grok Assistant</h4>
              <Button
                variant="ghost" 
                size="sm"
                onClick={() => setIsOpen(false)}
                className="text-white hover:text-gray-200 p-0"
              >
                <XIcon className="w-5 h-5" />
              </Button>
            </CardHeader>
            
            <CardContent className="p-0">
              {/* Messages */}
              <div className="h-64 overflow-y-auto p-4 space-y-3 custom-scrollbar">
                {messages.map((message) => (
                  <div key={message.id} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div
                      className={`max-w-xs p-3 rounded-lg text-sm ${
                        message.role === 'user'
                          ? 'bg-primary text-white'
                          : 'bg-muted text-foreground'
                      }`}
                    >
                      {message.content}
                    </div>
                  </div>
                ))}
                
                {sendMessageMutation.isPending && (
                  <div className="flex justify-start">
                    <div className="bg-muted p-3 rounded-lg text-sm text-foreground">
                      <div className="flex space-x-1">
                        <div className="w-2 h-2 bg-current rounded-full animate-bounce"></div>
                        <div className="w-2 h-2 bg-current rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                        <div className="w-2 h-2 bg-current rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              
              {/* Input */}
              <div className="p-4 border-t border-border">
                <div className="flex space-x-2">
                  <Input
                    type="text"
                    placeholder="Ask me anything..."
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyPress={handleKeyPress}
                    className="flex-1 text-sm"
                    disabled={sendMessageMutation.isPending}
                  />
                  <Button
                    onClick={handleSendMessage}
                    disabled={!input.trim() || sendMessageMutation.isPending}
                    size="sm"
                    className="bg-accent text-white hover:bg-purple-600"
                  >
                    <SendIcon className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </>
  );
}
