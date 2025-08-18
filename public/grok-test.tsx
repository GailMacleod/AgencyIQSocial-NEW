import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle, Check } from "lucide-react";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { format } from "date-fns";
import Header from "@/components/header";

export default function AITest() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showAIThinking, setShowAIThinking] = useState(false);
  const [aiStep, setAIStep] = useState(0);
  const [generatedPosts, setGeneratedPosts] = useState<any[]>([]);
  const [approvedPosts, setApprovedPosts] = useState<Set<number>>(new Set());

  const aiThinkingSteps = [
    {
      step: 1,
      title: "Analyzing Brand Purpose & Goals",
      content: "Your little helper is reviewing your brand purpose to understand core messaging, target audience, and business objectives...",
      duration: 2000
    },
    {
      step: 2, 
      title: "Platform Strategy Analysis",
      content: "Evaluating which social media platforms best align with your goals: LinkedIn for B2B reach, Instagram for visual storytelling, Facebook for community building...",
      duration: 3000
    },
    {
      step: 3,
      title: "Queensland Event Integration", 
      content: "Cross-referencing local Queensland events, school holidays, and seasonal opportunities to optimise posting timing...",
      duration: 2500
    },
    {
      step: 4,
      title: "Content Creation & Refinement",
      content: "Generating platform-specific content that reflects your brand voice while maximizing engagement potential...",
      duration: 4000
    },
    {
      step: 5,
      title: "Final Review & Optimization",
      content: "Applying unpaid media best practices and ensuring each post meets your strategic objectives...",
      duration: 2000
    }
  ];

  const generateContentWithAIThinking = async () => {
    setShowAIThinking(true);
    setAIStep(0);
    
    try {
      // Simulate AI's thinking process
      for (let i = 0; i < aiThinkingSteps.length; i++) {
        setAIStep(i + 1);
        await new Promise(resolve => setTimeout(resolve, aiThinkingSteps[i].duration));
      }
      
      // Generate real content using AI API
      const response = await apiRequest("POST", "/api/ai/generate-content", {});
      const data = await response.json();
      const aiPosts = data.posts.map((post: any, index: number) => ({
        id: index + 1,
        platform: post.platform,
        content: post.content,
        status: "scheduled",
        scheduledFor: post.scheduledFor,
        aiRecommendation: `AI generated this ${post.platform} post based on your brand purpose analysis`
      }));
      
      setGeneratedPosts(aiPosts);
    } catch (error: any) {
      toast({
        title: "Content Generation Failed",
        description: error.message || "Unable to generate content with AI",
        variant: "destructive",
      });
    } finally {
      setShowAIThinking(false);
    }
  };

  const approvePostMutation = useMutation({
    mutationFn: async (postId: number) => {
      const response = await apiRequest("POST", "/api/posts/approve", { postId });
      return await response.json();
    },
    onSuccess: (data, postId) => {
      setApprovedPosts(prev => new Set(Array.from(prev).concat(postId)));
      toast({
        title: "Post Approved",
        description: `Post scheduled for publishing. Remaining posts: ${data.remainingPosts}`,
      });
    },
    onError: (error: any) => {
      toast({
        title: "Approval Failed",
        description: error.message || "Failed to approve post",
        variant: "destructive",
      });
    },
  });

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case "linkedin":
        return <div className="w-8 h-8 bg-blue-600 rounded text-white flex items-center justify-center text-sm font-bold">Li</div>;
      case "instagram":
        return <div className="w-8 h-8 bg-pink-600 rounded text-white flex items-center justify-center text-sm font-bold">Ig</div>;
      case "facebook":
        return <div className="w-8 h-8 bg-blue-700 rounded text-white flex items-center justify-center text-sm font-bold">Fb</div>;
      default:
        return <div className="w-8 h-8 bg-gray-600 rounded text-white flex items-center justify-center text-sm font-bold">?</div>;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Header showBack="/" title="AI Content Generation Test" />
      
      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-light text-gray-900 mb-4">
            AI Content Generation Workflow
          </h1>
          <p className="text-gray-600 text-sm">
            Watch AI analyse your brand purpose and create strategic social media content
          </p>
          
          <Button
            onClick={generateContentWithAIThinking}
            className="mt-6 bg-purple-600 hover:bg-purple-700 text-white px-8 py-3"
            disabled={showAIThinking}
          >
            {showAIThinking ? 'AI is thinking...' : 'Generate Content with AI'}
          </Button>
        </div>

        {/* AI Thinking Process Modal */}
        {showAIThinking && (
          <div className="fixed inset-0 z-50 bg-black bg-opacity-50 flex items-center justify-center p-4">
            <Card className="max-w-2xl w-full bg-white">
              <CardContent className="p-8">
                <div className="text-center">
                  <h2 className="text-2xl font-light text-purple-700 mb-6">
                    AI Strategic Analysis
                  </h2>
                  
                  {/* Progress Steps */}
                  <div className="space-y-6">
                    {aiThinkingSteps.map((step, index) => (
                      <div 
                        key={index}
                        className={`flex items-start space-x-4 p-4 rounded-lg transition-all duration-500 border ${
                          aiStep > index ? 'bg-green-50 border-green-200' :
                          aiStep === index + 1 ? 'bg-purple-50 border-purple-200 shadow-md' :
                          'bg-gray-50 border-gray-200'
                        }`}
                      >
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                          aiStep > index ? 'bg-green-500 text-white' :
                          aiStep === index + 1 ? 'bg-purple-500 text-white animate-pulse' :
                          'bg-gray-300 text-gray-600'
                        }`}>
                          {aiStep > index ? '✓' : step.step}
                        </div>
                        <div className="flex-1 text-left">
                          <h3 className="font-medium text-gray-900">{step.title}</h3>
                          <p className="text-sm text-gray-600 mt-1">{step.content}</p>
                        </div>
                        {aiStep === index + 1 && (
                          <div className="animate-spin w-4 h-4 border-2 border-purple-600 border-t-transparent rounded-full"></div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Generated Posts Preview */}
        {generatedPosts.length > 0 && (
          <div className="mt-8">
            <h2 className="text-xl font-light text-gray-900 mb-4 lowercase">
              grok's content recommendations
            </h2>
            <div className="grid gap-6">
              {generatedPosts.map((post) => (
                <Card key={post.id} className="p-6">
                  <CardContent className="p-0">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        {getPlatformIcon(post.platform)}
                        <div>
                          <h3 className="font-medium text-gray-900">{post.platform}</h3>
                          <p className="text-sm text-gray-500">
                            scheduled for {format(new Date(post.scheduledFor), 'MMM d, h:mm a')}
                          </p>
                        </div>
                      </div>
                      <Badge variant="outline">
                        {post.status}
                      </Badge>
                    </div>
                    
                    <div className="mb-4">
                      <p className="text-gray-800 whitespace-pre-wrap">{post.content}</p>
                    </div>
                    
                    {post.grokRecommendation && (
                      <div className="bg-purple-50 border border-purple-200 rounded-lg p-3 mb-4">
                        <p className="text-purple-700 text-sm font-medium">Grok's Strategy:</p>
                        <p className="text-purple-800 text-sm">{post.grokRecommendation}</p>
                      </div>
                    )}
                    
                    <div className="flex space-x-3">
                      {approvedPosts.has(post.id) ? (
                        <div className="flex items-center space-x-2 px-4 py-2 bg-green-100 border border-green-300 rounded-md">
                          <div className="w-6 h-6 bg-green-500 rounded-full flex items-center justify-center animate-pulse">
                            <Check className="w-4 h-4 text-white" />
                          </div>
                          <span className="text-green-700 font-medium">Approved & Scheduled</span>
                        </div>
                      ) : (
                        <Button
                          onClick={() => approvePostMutation.mutate(post.id)}
                          className="bg-green-600 hover:bg-green-700 text-white"
                          disabled={approvePostMutation.isPending}
                        >
                          <CheckCircle className="w-4 h-4 mr-2" />
                          {approvePostMutation.isPending ? 'Approving...' : 'Approve & Schedule'}
                        </Button>
                      )}
                      <Button
                        variant="outline"
                        disabled={approvedPosts.has(post.id)}
                      >
                        Edit Post
                      </Button>
                      <Button
                        variant="outline"
                        className="text-red-600 border-red-200 hover:bg-red-50"
                        disabled={approvedPosts.has(post.id)}
                      >
                        Reject
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}