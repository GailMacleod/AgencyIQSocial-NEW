import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { Video, Play, Pause, Download, Wand2, Sparkles, Camera, Film, Crown, Lock } from "lucide-react";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";
import BackButton from "@/components/back-button";
import OnboardingWizard from "@/components/onboarding/OnboardingWizard";

interface VideoGenerationRequest {
  prompt: string;
  style: 'cinematic' | 'documentary' | 'tech-showcase' | 'asmr';
  duration: number;
  platform: string;
  brandContext?: string;
}

interface GeneratedVideo {
  id: string;
  url: string;
  thumbnail: string;
  title: string;
  status: 'generating' | 'ready' | 'failed';
  platform: string;
  style: string;
  duration: number;
  createdAt: string;
}

function VideoGeneration() {
  const [prompt, setPrompt] = useState("");
  const [selectedStyle, setSelectedStyle] = useState<'cinematic' | 'documentary' | 'tech-showcase' | 'asmr'>('cinematic');
  const [selectedPlatform, setSelectedPlatform] = useState("instagram");
  const [duration, setDuration] = useState(15);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationProgress, setGenerationProgress] = useState(0);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch user subscription status for video access control
  const { data: user } = useQuery({
    queryKey: ["/api/user"],
  });

  // Pro subscription check - only pro users can access video generation
  const hasProSubscription = user?.subscriptionPlan === 'professional' || user?.subscriptionPlan === 'pro';

  const { data: videos, isLoading } = useQuery<GeneratedVideo[]>({
    queryKey: ["/api/videos"],
    refetchInterval: 2000, // Poll while generating
  });

  const { data: brandPurpose } = useQuery({
    queryKey: ["/api/brand-purpose"],
  });

  // Integrated workflow: Grok enhancement → VEO 3.0 rendering
  const generateAndRenderVideo = async (postContent: string, platform: string, userId: number) => {
    try {
      console.log('🎬 Starting integrated video workflow: Grok → VEO 3.0');
      
      // Step 1: Generate enhanced prompts with Grok copywriter
      const promptResponse = await fetch('/api/video/generate-prompts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ postContent, platform, userId })
      });
      
      if (!promptResponse.ok) throw new Error('Prompt generation failed');
      
      const promptData = await promptResponse.json();
      const enhancedPrompt = promptData.prompts?.[0]?.prompt || promptData.enhancedCopy || 'Professional Queensland business video';
      
      console.log('✅ Grok enhancement completed, starting VEO 3.0 rendering...');
      
      // Step 2: Render video with enhanced prompt
      const renderResponse = await fetch('/api/video/render', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          prompt: enhancedPrompt, 
          platform, 
          userId,
          grokEnhanced: true,
          originalContent: postContent
        })
      });
      
      if (!renderResponse.ok) throw new Error('Video rendering failed');
      
      const videoData = await renderResponse.json();
      console.log('✅ Integrated workflow completed:', videoData.videoUrl);
      return videoData;
      
    } catch (error) {
      console.error('❌ Integrated workflow error:', error);
      throw error;
    }
  };

  const generateVideoMutation = useMutation({
    mutationFn: async (request: VideoGenerationRequest) => {
      // Use VEO 3.0 direct integration with GEMINI_API_KEY
      return await generateAndRenderVideo(request.prompt, request.platform, 2);
    },
    onSuccess: (data) => {
      toast({
        title: "🎬 VEO 3.0 Generation Started",
        description: "Cinematic video with Gemini enhancement and VEO 3.0 is generating. Processing time: 30s-6 minutes.",
      });
      setIsGenerating(true);
      setGenerationProgress(0);
      queryClient.invalidateQueries({ queryKey: ["/api/videos"] });
    },
    onError: (error: any) => {
      toast({
        title: "VEO 3.0 Generation Failed",
        description: error.message || "Failed to start VEO 3.0 video generation",
        variant: "destructive",
      });
    },
  });

  // Mock progress simulation
  useEffect(() => {
    if (isGenerating) {
      const interval = setInterval(() => {
        setGenerationProgress(prev => {
          if (prev >= 95) {
            clearInterval(interval);
            return 95;
          }
          return prev + Math.random() * 5;
        });
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [isGenerating]);

  // Check if generation is complete
  useEffect(() => {
    if (videos && videos.length > 0) {
      const latestVideo = videos[0];
      if (latestVideo.status === 'ready' && isGenerating) {
        setIsGenerating(false);
        setGenerationProgress(100);
        toast({
          title: "Video Ready!",
          description: `Your ${latestVideo.style} video has been generated successfully.`,
        });
      }
    }
  }, [videos, isGenerating, toast]);

  const handleGenerate = () => {
    if (!prompt.trim()) {
      toast({
        title: "Prompt Required",
        description: "Please enter a description for your video",
        variant: "destructive",
      });
      return;
    }

    generateVideoMutation.mutate({
      prompt,
      style: selectedStyle,
      duration,
      platform: selectedPlatform,
      brandContext: (brandPurpose as any)?.corePurpose || ""
    });
  };

  const videoStyles = [
    {
      value: 'cinematic',
      label: 'Epic Cinematic',
      description: 'Blockbuster movie trailer style with dramatic effects',
      icon: <Film className="w-4 h-4" />
    },
    {
      value: 'documentary',
      label: 'Professional Documentary',
      description: 'Behind-the-scenes documentary with natural lighting',
      icon: <Camera className="w-4 h-4" />
    },
    {
      value: 'tech-showcase',
      label: 'Tech Showcase',
      description: 'Futuristic technology demo with digital effects',
      icon: <Sparkles className="w-4 h-4" />
    },
    {
      value: 'asmr',
      label: 'Strategic ASMR',
      description: 'Soothing business-focused content with whispered narration',
      icon: <Wand2 className="w-4 h-4" />
    }
  ];

  const platforms = [
    { value: 'instagram', label: 'Instagram', ratio: '9:16' },
    { value: 'youtube', label: 'YouTube', ratio: '16:9' },
    { value: 'facebook', label: 'Facebook', ratio: '16:9' },
    { value: 'linkedin', label: 'LinkedIn', ratio: '16:9' },
    { value: 'x', label: 'X (Twitter)', ratio: '16:9' }
  ];

  return (
    <div className="min-h-screen bg-background">
      <MasterHeader />
      <BackButton />
      
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <div className="flex items-center space-x-3 mb-4">
            <h1 className="text-3xl font-bold">VEO 3.0 Video Generation</h1>
            <Badge variant="secondary" className="bg-gradient-to-r from-blue-500 to-purple-600 text-white">
              ✨ Powered by Google VEO 3.0
            </Badge>
          </div>
          <p className="text-muted-foreground">
            Create cinematic-quality videos with Google's VEO 3.0 AI and Gemini enhancement. 
            Features orchestral music, Queensland business context, and authentic 30s-6min processing.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Generation Form */}
          <Card className="card-agencyiq">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Video className="w-5 h-5" />
                <span>VEO 3.0 Video Generator</span>
                <Badge variant="outline" className="ml-2">Gemini + VEO 3.0</Badge>
              </CardTitle>
              <p className="text-sm text-muted-foreground">
                Enhanced with Queensland business context and JTBD framework
              </p>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <label className="text-sm font-medium mb-2 block">Video Description</label>
                <Textarea
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder="Describe your Queensland business video... VEO 3.0 will create cinematic quality with orchestral music (e.g., 'Professional business transformation meeting with Australian executives')"
                  className="min-h-24"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Video Style</label>
                  <Select value={selectedStyle} onValueChange={(value: any) => setSelectedStyle(value)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {videoStyles.map((style) => (
                        <SelectItem key={style.value} value={style.value}>
                          <div className="flex items-center space-x-2">
                            {style.icon}
                            <div>
                              <div className="font-medium">{style.label}</div>
                              <div className="text-xs text-muted-foreground">{style.description}</div>
                            </div>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <label className="text-sm font-medium mb-2 block">Target Platform</label>
                  <Select value={selectedPlatform} onValueChange={setSelectedPlatform}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {platforms.map((platform) => (
                        <SelectItem key={platform.value} value={platform.value}>
                          {platform.label} ({platform.ratio})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div>
                <label className="text-sm font-medium mb-2 block">Duration: {duration}s</label>
                <input
                  type="range"
                  min="5"
                  max="60"
                  value={duration}
                  onChange={(e) => setDuration(parseInt(e.target.value))}
                  className="w-full"
                />
              </div>

              {isGenerating && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">VEO 3.0 Generating...</span>
                    <span className="text-sm text-muted-foreground">{Math.round(generationProgress)}%</span>
                  </div>
                  <Progress value={generationProgress} className="w-full" />
                  <div className="p-2 bg-amber-50 border border-amber-200 rounded text-xs text-amber-800">
                    <strong>Please wait:</strong> VEO 3.0 async processing takes 30 seconds to 6 minutes for cinematic quality.
                  </div>
                </div>
              )}

              {hasProSubscription ? (
                <Button
                  onClick={handleGenerate}
                  disabled={isGenerating || generateVideoMutation.isPending}
                  className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
                >
                  {isGenerating ? "🎬 VEO 3.0 Generating..." : "🚀 Generate with VEO 3.0"}
                </Button>
              ) : (
                <div className="space-y-3">
                  <Button
                    disabled
                    className="w-full bg-gradient-to-r from-amber-500 to-orange-500 text-white opacity-75 cursor-not-allowed"
                  >
                    <Lock className="w-5 h-5 mr-2" />
                    Pro Feature Required
                    <Crown className="w-4 h-4 ml-2" />
                  </Button>
                  <div className="p-4 bg-gradient-to-r from-amber-50 to-orange-50 border-2 border-amber-200 rounded-lg text-center">
                    <Crown className="w-8 h-8 mx-auto mb-2 text-amber-600" />
                    <h3 className="font-semibold text-amber-800 mb-1">Upgrade to Pro for VEO 3.0</h3>
                    <p className="text-sm text-amber-700 mb-3">
                      Access cinematic video generation with Queensland business context, orchestral music, and authentic VEO 3.0 processing
                    </p>
                    <Button 
                      onClick={() => window.location.href = '/pricing'}
                      className="bg-amber-600 hover:bg-amber-700 text-white"
                      size="sm"
                    >
                      <Crown className="w-4 h-4 mr-1" />
                      Upgrade Now
                    </Button>
                  </div>
                </div>
              )}
              
              <div className="text-xs text-center text-muted-foreground space-y-1">
                <p>🎵 <strong>Automatic Features:</strong> Orchestral music, Queensland context, cinematic quality</p>
                <p>⏱️ <strong>Processing Time:</strong> 30 seconds to 6 minutes for authentic VEO 3.0 quality</p>
                <p>🤖 <strong>AI Engine:</strong> Gemini enhancement → VEO 3.0 generation → JTBD framework</p>
              </div>
            </CardContent>
          </Card>

          {/* Generated Videos */}
          <Card className="card-agencyiq">
            <CardHeader>
              <CardTitle>Your Generated Videos</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-4">
                  {[...Array(3)].map((_, i) => (
                    <div key={i} className="animate-pulse">
                      <div className="bg-muted rounded-lg aspect-video"></div>
                      <div className="h-4 bg-muted rounded mt-2"></div>
                    </div>
                  ))}
                </div>
              ) : videos && videos.length > 0 ? (
                <div className="space-y-4">
                  {videos.map((video) => (
                    <div key={video.id} className="border rounded-lg p-4">
                      <div className="aspect-video bg-muted rounded-lg mb-3 relative">
                        {video.status === 'ready' ? (
                          <div className="absolute inset-0 flex items-center justify-center">
                            <Button variant="outline" size="sm">
                              <Play className="w-4 h-4 mr-2" />
                              Play Video
                            </Button>
                          </div>
                        ) : (
                          <div className="absolute inset-0 flex items-center justify-center">
                            <div className="text-center">
                              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-2"></div>
                              <div className="text-sm text-muted-foreground">Generating...</div>
                            </div>
                          </div>
                        )}
                      </div>
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="font-medium">{video.title}</h3>
                          <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                            <Badge variant="outline">{video.style}</Badge>
                            <Badge variant="outline">{video.platform}</Badge>
                            <span>{video.duration}s</span>
                          </div>
                        </div>
                        {video.status === 'ready' && (
                          <Button variant="outline" size="sm">
                            <Download className="w-4 h-4" />
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Video className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">No videos generated yet</p>
                  <p className="text-sm text-muted-foreground mt-1">Create your first video to get started</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <MasterFooter />
      <OnboardingWizard />
    </div>
  );
}

export default VideoGeneration;