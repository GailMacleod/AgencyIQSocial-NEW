import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Plus, CheckCircle, BarChart3, Settings, Zap } from "lucide-react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";

interface QuickActionsPanelProps {
  remainingPosts?: number;
  totalPosts?: number;
}

export function QuickActionsPanel({ remainingPosts = 0, totalPosts = 30 }: QuickActionsPanelProps) {
  const [, setLocation] = useLocation();

  const { data: quotaData } = useQuery({
    queryKey: ['/api/subscription-usage'],
    enabled: true
  });

  const actualRemaining = quotaData?.remainingPosts ?? remainingPosts;
  const actualTotal = quotaData?.totalAllocation ?? totalPosts;

  const quickActions = [
    {
      id: 'generate',
      icon: Plus,
      label: 'Generate Content',
      description: 'Create AI-powered posts',
      onClick: () => setLocation('/intelligent-schedule'),
      color: 'bg-purple-600 hover:bg-purple-700',
      disabled: actualRemaining <= 0
    },
    {
      id: 'approve',
      icon: CheckCircle,
      label: 'Approve Posts',
      description: 'Review and approve content',
      onClick: () => setLocation('/schedule'),
      color: 'bg-green-600 hover:bg-green-700'
    },
    {
      id: 'analytics',
      icon: BarChart3,
      label: 'View Analytics',
      description: 'Track performance metrics',
      onClick: () => setLocation('/yearly-analytics'),
      color: 'bg-blue-600 hover:bg-blue-700'
    },
    {
      id: 'connections',
      icon: Settings,
      label: 'Platform Setup',
      description: 'Manage social accounts',
      onClick: () => setLocation('/token-status'),
      color: 'bg-orange-600 hover:bg-orange-700'
    }
  ];

  return (
    <Card className="mb-6">
      <CardContent className="p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900">Quick Actions</h2>
          <div className="flex items-center space-x-2">
            <Zap className="w-4 h-4 text-yellow-500" />
            <span className="text-sm text-gray-600">
              {actualRemaining} of {actualTotal} posts remaining
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {quickActions.map((action) => (
            <Button
              key={action.id}
              onClick={action.onClick}
              disabled={action.disabled}
              aria-label={`${action.label}: ${action.description}`}
              className={`${action.color} text-white h-auto p-4 flex flex-col items-center space-y-2 hover:scale-105 transition-transform`}
            >
              <action.icon className="w-6 h-6" />
              <div className="text-center">
                <div className="font-medium text-sm">{action.label}</div>
                <div className="text-xs opacity-90">{action.description}</div>
              </div>
            </Button>
          ))}
        </div>

        {actualRemaining <= 0 && (
          <div className="mt-4 p-3 bg-amber-50 border border-amber-200 rounded-lg">
            <div className="flex items-center space-x-2">
              <Zap className="w-4 h-4 text-amber-600" />
              <span className="text-sm text-amber-800">
                Quota reached. <Button variant="link" className="p-0 h-auto text-amber-800 underline" onClick={() => setLocation('/subscription')}>
                  Upgrade your plan
                </Button> to continue generating content.
              </span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}