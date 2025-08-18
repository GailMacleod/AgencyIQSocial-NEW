import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useQuery } from '@tanstack/react-query';

export default function BrandPurpose({ posts = [], user = null }) {
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [editingPost, setEditingPost] = useState(null);
  const [editContent, setEditContent] = useState('');
  
  // Strategyzer Brand Purpose data collection
  const [brandPurposeData, setBrandPurposeData] = useState({
    goals: {
      awareness: '',
      engagement: '',
      conversion: '',
      retention: ''
    },
    targets: {
      demographic: '',
      geographic: '',
      psychographic: '',
      behavioral: ''
    },
    text: ''
  });

  // Fetch existing brand purpose data
  const { data: existingBrandPurpose } = useQuery({
    queryKey: ['/api/brand-purpose'],
    enabled: !!user
  });

  useEffect(() => {
    if (existingBrandPurpose) {
      setBrandPurposeData(prev => ({
        ...prev,
        text: existingBrandPurpose.corePurpose || ''
      }));
    }
  }, [existingBrandPurpose]);

  // Global data synchronization on component load
  useEffect(() => {
    const syncData = async () => {
      if (user?.id) {
        try {
          const adminToken = 'admin_cleanup_token_2025';
          const response = await fetch('/api/sync-all-user-data', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${adminToken}`,
              'Content-Type': 'application/json'
            },
            credentials: 'include'
          });

          if (response.ok) {
            const result = await response.json();
            console.log(`Customer data populated for ${user.id || 'unknown'}:`, result);
          } else {
            console.warn('Data sync permission denied or failed');
          }
        } catch (error) {
          console.error('Global data sync failed:', error);
        }
      }
    };
    
    syncData();
  }, [user?.id]);

  const handleEditClick = (post) => {
    console.log('Edit clicked for', post.platform);
    setEditingPost(post);
    setEditContent(post.content);
    setIsEditModalOpen(true);
  };

  const handleSaveEdit = () => {
    console.log('Saving edited content for', editingPost?.platform, ':', editContent);
    setIsEditModalOpen(false);
    setEditingPost(null);
    setEditContent('');
  };

  const handleGenerateSchedule = async () => {
    if (!user?.email) return;

    // Marketing essentials enforced on client side
    const marketingEssentials = {
      job: 'automate 30-day marketing',
      services: 'social media automation, platform connections',
      tone: 'professional, supportive'
    };

    const fullBrandPurpose = {
      goals: brandPurposeData.goals,
      targets: brandPurposeData.targets,
      text: brandPurposeData.text,
      brandPurpose: existingBrandPurpose,
      ...marketingEssentials
    };

    console.log(`Full Brand Purpose with essentials sent for ${user.email}: [goals: ${JSON.stringify(brandPurposeData.goals)}, targets: ${JSON.stringify(brandPurposeData.targets)}, text: ${brandPurposeData.text}, job: ${marketingEssentials.job}, services: ${marketingEssentials.services}, tone: ${marketingEssentials.tone}]`);

    try {
      const response = await fetch('/api/brand-posts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(fullBrandPurpose)
      });

      const result = await response.json();
      if (result.success) {
        console.log('Schedule generation complete with Strategyzer insights and marketing essentials');
      }
    } catch (error) {
      console.error('Failed to generate schedule:', error);
    }
  };

  return (
    <div className="space-y-6">
      {/* Strategyzer Brand Purpose Collection Form */}
      <Card className="w-full">
        <CardHeader>
          <CardTitle>Brand Purpose Strategyzer</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Goals Section */}
          <div className="space-y-4">
            <Label className="text-base font-semibold">Strategic Goals</Label>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="awareness">Brand Awareness</Label>
                <Input
                  id="awareness"
                  value={brandPurposeData.goals.awareness}
                  onChange={(e) => setBrandPurposeData(prev => ({
                    ...prev,
                    goals: { ...prev.goals, awareness: e.target.value }
                  }))}
                  placeholder="Increase brand visibility..."
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="engagement">Engagement</Label>
                <Input
                  id="engagement"
                  value={brandPurposeData.goals.engagement}
                  onChange={(e) => setBrandPurposeData(prev => ({
                    ...prev,
                    goals: { ...prev.goals, engagement: e.target.value }
                  }))}
                  placeholder="Drive meaningful interactions..."
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="conversion">Conversion</Label>
                <Input
                  id="conversion"
                  value={brandPurposeData.goals.conversion}
                  onChange={(e) => setBrandPurposeData(prev => ({
                    ...prev,
                    goals: { ...prev.goals, conversion: e.target.value }
                  }))}
                  placeholder="Generate leads and sales..."
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="retention">Customer Retention</Label>
                <Input
                  id="retention"
                  value={brandPurposeData.goals.retention}
                  onChange={(e) => setBrandPurposeData(prev => ({
                    ...prev,
                    goals: { ...prev.goals, retention: e.target.value }
                  }))}
                  placeholder="Build customer loyalty..."
                />
              </div>
            </div>
          </div>

          {/* Targets Section */}
          <div className="space-y-4">
            <Label className="text-base font-semibold">Target Segmentation</Label>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="demographic">Demographic</Label>
                <Input
                  id="demographic"
                  value={brandPurposeData.targets.demographic}
                  onChange={(e) => setBrandPurposeData(prev => ({
                    ...prev,
                    targets: { ...prev.targets, demographic: e.target.value }
                  }))}
                  placeholder="Age, gender, income..."
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="geographic">Geographic</Label>
                <Input
                  id="geographic"
                  value={brandPurposeData.targets.geographic}
                  onChange={(e) => setBrandPurposeData(prev => ({
                    ...prev,
                    targets: { ...prev.targets, geographic: e.target.value }
                  }))}
                  placeholder="Location, region..."
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="psychographic">Psychographic</Label>
                <Input
                  id="psychographic"
                  value={brandPurposeData.targets.psychographic}
                  onChange={(e) => setBrandPurposeData(prev => ({
                    ...prev,
                    targets: { ...prev.targets, psychographic: e.target.value }
                  }))}
                  placeholder="Values, interests, lifestyle..."
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="behavioral">Behavioral</Label>
                <Input
                  id="behavioral"
                  value={brandPurposeData.targets.behavioral}
                  onChange={(e) => setBrandPurposeData(prev => ({
                    ...prev,
                    targets: { ...prev.targets, behavioral: e.target.value }
                  }))}
                  placeholder="Purchase behavior, usage..."
                />
              </div>
            </div>
          </div>

          {/* Core Text Section */}
          <div className="space-y-4">
            <Label className="text-base font-semibold">Brand Purpose Statement</Label>
            <Textarea
              value={brandPurposeData.text}
              onChange={(e) => setBrandPurposeData(prev => ({
                ...prev,
                text: e.target.value
              }))}
              placeholder="Define your brand's core purpose and mission..."
              rows={4}
              className="resize-none"
            />
          </div>

          <Button 
            onClick={handleGenerateSchedule}
            className="w-full"
            disabled={!brandPurposeData.text.trim()}
          >
            Generate AI Schedule with Strategyzer Analysis
          </Button>
        </CardContent>
      </Card>

      {/* Posts Display */}
      {posts.map((post) => (
        <Card key={post.id} className="w-full">
          <CardHeader>
            <CardTitle className="flex justify-between items-center">
              <span>{post.platform}</span>
              <Button 
                variant="outline" 
                size="sm"
                onClick={() => handleEditClick(post)}
              >
                Edit Content
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-gray-600">{post.content}</p>
          </CardContent>
        </Card>
      ))}

      <Dialog open={isEditModalOpen} onOpenChange={setIsEditModalOpen}>
        <DialogContent className="sm:max-w-[525px]">
          <DialogHeader>
            <DialogTitle>Edit {editingPost?.platform} Content</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <Textarea
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              placeholder="Enter your post content..."
              rows={6}
              className="resize-none"
            />
          </div>
          <div className="flex justify-end space-x-2">
            <Button variant="outline" onClick={() => setIsEditModalOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleSaveEdit}>
              Save Changes
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}