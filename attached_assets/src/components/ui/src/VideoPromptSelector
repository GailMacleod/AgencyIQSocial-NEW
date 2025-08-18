import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { VideoIcon, Sparkles } from 'lucide-react';
import { VideoPrompt } from '@/types';

interface VideoPromptSelectorProps {
  prompts: VideoPrompt[];
  onSelect: (prompt: VideoPrompt) => void;
  isLoading?: boolean;
}

export function VideoPromptSelector({ prompts, onSelect, isLoading }: VideoPromptSelectorProps): JSX.Element {
  const [selectedPrompt, setSelectedPrompt] = useState<VideoPrompt | null>(null);

  const handleSelect = (prompt: VideoPrompt): void => {
    setSelectedPrompt(prompt);
    onSelect(prompt);
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <VideoIcon className="w-5 h-5" />
            Generating Video Options...
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="animate-pulse space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-20 bg-gray-200 rounded-lg" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="w-5 h-5" />
          Choose Your Video Style
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {prompts.map((prompt, index) => (
          <div
            key={index}
            className={`p-4 border rounded-lg cursor-pointer transition-all ${
              selectedPrompt === prompt
                ? 'border-blue-500 bg-blue-50'
                : 'border-gray-200 hover:border-gray-300'
            }`}
            onClick={() => handleSelect(prompt)}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant={prompt.type.includes('Epic') ? 'default' : 'secondary'}>
                    {prompt.type}
                  </Badge>
                  <span className="text-sm text-gray-600">{prompt.duration}</span>
                </div>
                <p className="text-sm text-gray-700 line-clamp-2">{prompt.content}</p>
                <p className="text-xs text-gray-500 mt-1">{prompt.style}</p>
              </div>
              <Button
                size="sm"
                variant={selectedPrompt === prompt ? 'default' : 'outline'}
                onClick={(e) => {
                  e.stopPropagation();
                  handleSelect(prompt);
                }}
              >
                Select
              </Button>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}