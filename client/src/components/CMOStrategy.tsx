import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Target, Zap, TrendingUp, Users, DollarSign, Clock } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { apiRequest } from '@/lib/queryClient';

interface CMOStrategyProps {
  brandPurpose: any;
  onStrategyGenerated?: (posts: any[]) => void;
}

export default function CMOStrategy({ brandPurpose, onStrategyGenerated }: CMOStrategyProps) {
  const [isGenerating, setIsGenerating] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const generateCMOStrategy = useMutation({
    mutationFn: async () => {
      setIsGenerating(true);
      const response = await fetch('/api/generate-cmo-strategy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          brandPurpose,
          totalPosts: 30,
          platforms: ['facebook', 'instagram', 'linkedin', 'youtube']
        })
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Failed to generate CMO strategy');
      }
      
      return response.json();
    },
    onSuccess: (data) => {
      setIsGenerating(false);
      toast({
        title: "Brand Domination Strategy Deployed",
        description: `${data.generatedCount} unstoppable posts generated for ${data.targetMetrics.salesTarget} sales target`,
        variant: "default",
      });
      
      // Invalidate and refetch posts
      queryClient.invalidateQueries({ queryKey: ['/api/posts'] });
      
      if (onStrategyGenerated) {
        onStrategyGenerated(data.posts);
      }
    },
    onError: (error: any) => {
      setIsGenerating(false);
      toast({
        title: "Strategy Generation Failed",
        description: error.message || "Failed to generate CMO strategy",
        variant: "destructive",
      });
    },
  });

  const handleGenerateStrategy = () => {
    if (!brandPurpose?.corePurpose) {
      toast({
        title: "Brand Purpose Required",
        description: "Complete your brand purpose setup first",
        variant: "destructive",
      });
      return;
    }
    
    generateCMOStrategy.mutate();
  };

  return (
    <Card className="border-2 border-orange-200 bg-gradient-to-br from-orange-50 to-red-50">
      <CardHeader>
        <div className="flex items-center space-x-2">
          <Target className="w-6 h-6 text-orange-600" />
          <CardTitle className="text-xl text-orange-800">CMO Brand Domination Strategy</CardTitle>
        </div>
        <CardDescription className="text-orange-700">
          Unleash unstoppable content that annihilates competition and explodes sales
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Strategy Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex items-center space-x-3 p-3 bg-white/60 rounded-lg">
            <DollarSign className="w-5 h-5 text-green-600" />
            <div>
              <p className="text-sm font-medium">Sales Target</p>
              <p className="text-lg font-bold text-green-700">$10,000/month</p>
            </div>
          </div>
          
          <div className="flex items-center space-x-3 p-3 bg-white/60 rounded-lg">
            <TrendingUp className="w-5 h-5 text-blue-600" />
            <div>
              <p className="text-sm font-medium">Conversion Rate</p>
              <p className="text-lg font-bold text-blue-700">3%</p>
            </div>
          </div>
          
          <div className="flex items-center space-x-3 p-3 bg-white/60 rounded-lg">
            <Clock className="w-5 h-5 text-purple-600" />
            <div>
              <p className="text-sm font-medium">Setup Time</p>
              <p className="text-lg font-bold text-purple-700">10 minutes</p>
            </div>
          </div>
        </div>

        {/* CMO Team Insights */}
        <div className="space-y-3">
          <h4 className="font-semibold text-orange-800">Executive Team Strategy</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            <Badge variant="outline" className="justify-center p-2">
              <Users className="w-4 h-4 mr-1" />
              CMO Strategy
            </Badge>
            <Badge variant="outline" className="justify-center p-2">
              <Zap className="w-4 h-4 mr-1" />
              Creative Direction
            </Badge>
            <Badge variant="outline" className="justify-center p-2">
              <Target className="w-4 h-4 mr-1" />
              Copywriting
            </Badge>
            <Badge variant="outline" className="justify-center p-2">
              <TrendingUp className="w-4 h-4 mr-1" />
              Social Media
            </Badge>
          </div>
        </div>

        {/* Key Features */}
        <div className="space-y-2">
          <h4 className="font-semibold text-orange-800">Brand Domination Features</h4>
          <ul className="text-sm space-y-1 text-orange-700">
            <li>• Save businesses from marketing obscurity</li>
            <li>• Automate 30 days of marketing in 10 minutes</li>
            <li>• Strategic hashtags: #QueenslandBusiness #TheAgencyIQ</li>
            <li>• SEO keywords: brand domination, sales annihilation</li>
            <li>• Launch: June 11, 2025, 4:00 PM AEST</li>
          </ul>
        </div>

        {/* Generate Button */}
        <div className="pt-4 border-t border-orange-200">
          <Button 
            onClick={handleGenerateStrategy}
            disabled={isGenerating || !brandPurpose?.corePurpose}
            className="w-full bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white font-semibold py-3"
            size="lg"
          >
            {isGenerating ? (
              <>
                <Zap className="w-4 h-4 mr-2 animate-spin" />
                Deploying Brand Domination Strategy...
              </>
            ) : (
              <>
                <Target className="w-4 h-4 mr-2" />
                Deploy Unstoppable Content Strategy
              </>
            )}
          </Button>
        </div>

        {isGenerating && (
          <div className="text-center text-sm text-orange-600 animate-pulse">
            Analyzing brand purpose with CMO team insights...
            <br />
            Generating unstoppable content for market domination...
          </div>
        )}
      </CardContent>
    </Card>
  );
}