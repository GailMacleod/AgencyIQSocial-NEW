import { ReactNode, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { HelpCircle, X } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ContextualTooltipProps {
  term: string;
  explanation: string;
  children?: ReactNode;
  position?: 'top' | 'bottom' | 'left' | 'right';
}

export function ContextualTooltip({ 
  term, 
  explanation, 
  children, 
  position = 'top' 
}: ContextualTooltipProps) {
  const [isVisible, setIsVisible] = useState(false);

  const positionClasses = {
    top: 'bottom-full mb-2 left-1/2 transform -translate-x-1/2',
    bottom: 'top-full mt-2 left-1/2 transform -translate-x-1/2',
    left: 'right-full mr-2 top-1/2 transform -translate-y-1/2',
    right: 'left-full ml-2 top-1/2 transform -translate-y-1/2'
  };

  return (
    <div className="relative inline-block">
      <div 
        className="flex items-center space-x-1 cursor-help"
        onMouseEnter={() => setIsVisible(true)}
        onMouseLeave={() => setIsVisible(false)}
        onClick={() => setIsVisible(!isVisible)}
      >
        {children || (
          <>
            <span className="text-sm font-medium text-gray-700 border-b border-dotted border-gray-400">
              {term}
            </span>
            <HelpCircle className="w-3 h-3 text-gray-400" />
          </>
        )}
      </div>

      {isVisible && (
        <Card className={`absolute z-50 w-72 shadow-lg ${positionClasses[position]}`}>
          <CardContent className="p-3">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <h4 className="font-medium text-sm text-gray-900 mb-1">{term}</h4>
                <p className="text-xs text-gray-600">{explanation}</p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="p-0 h-auto ml-2"
                onClick={() => setIsVisible(false)}
                aria-label="Close help tooltip"
              >
                <X className="w-3 h-3" />
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// Predefined tooltip explanations for common terms
export const tooltipDefinitions = {
  'quota deduction': 'Posts only count toward your monthly limit when they are successfully published to social media platforms, not when created or approved.',
  'approval workflow': 'Two-step process: first approve posts for review, then publish to platforms. Only publishing consumes your quota.',
  'platform health': 'Shows if your social media accounts are properly connected and tokens are valid for posting.',
  'oauth refresh': 'Automatic renewal of social media login tokens to keep your accounts connected without manual re-authorization.',
  'ai generation': 'Content created using advanced AI based on your brand purpose and Queensland market insights.',
  'analytics collection': 'Real-time data gathered from social media platforms showing post performance and engagement metrics.',
  'subscription cycle': 'Your monthly post allowance runs on a 30-day cycle from your subscription date, not calendar months.',
  'split timing': 'System that separates post approval from quota usage - you can approve unlimited posts but only pay quota when publishing.'
};

// Quick tooltip component for common terms
export function QuickTooltip({ term }: { term: keyof typeof tooltipDefinitions }) {
  return (
    <ContextualTooltip 
      term={term}
      explanation={tooltipDefinitions[term]}
    />
  );
}