import { UseFormReturn } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { FormField, FormItem, FormLabel, FormControl, FormMessage } from '@/components/ui/form';
import { Target, TrendingUp, ShoppingCart, Users, BookOpen } from 'lucide-react';
import { BrandGoals } from '@/types';

interface BrandGoalsSectionProps {
  form: UseFormReturn<any>;
  goals: BrandGoals;
}

export function BrandGoalsSection({ form, goals }: BrandGoalsSectionProps): JSX.Element {
  const goalSections = [
    {
      id: 'driveTraffic',
      title: 'Drive Traffic',
      icon: TrendingUp,
      description: 'Increase website visits',
      fields: [
        { name: 'websiteUrl', label: 'Website URL', placeholder: 'https://example.com' },
        { name: 'trafficTarget', label: 'Monthly Traffic Target', placeholder: '1,000 visitors' },
      ],
    },
    {
      id: 'buildBrand',
      title: 'Build Brand Awareness',
      icon: Target,
      description: 'Grow your audience and reach',
      fields: [
        { name: 'followerTarget', label: 'Follower Growth Target', placeholder: '500 new followers' },
        { name: 'reachTarget', label: 'Monthly Reach Target', placeholder: '10,000 people' },
      ],
    },
    {
      id: 'makeSales',
      title: 'Generate Sales',
      icon: ShoppingCart,
      description: 'Drive direct sales',
      fields: [
        { name: 'salesUrl', label: 'Sales Page URL', placeholder: 'https://shop.example.com' },
        { name: 'salesTarget', label: 'Monthly Sales Target', placeholder: '$5,000' },
        { name: 'conversionTarget', label: 'Conversion Rate Target', placeholder: '3%' },
      ],
    },
    {
      id: 'generateLeads',
      title: 'Generate Leads',
      icon: Users,
      description: 'Capture potential customers',
      fields: [
        { name: 'leadTarget', label: 'Monthly Lead Target', placeholder: '50 leads' },
        { name: 'engagementTarget', label: 'Engagement Rate Target', placeholder: '5%' },
      ],
    },
    {
      id: 'informEducate',
      title: 'Inform & Educate',
      icon: BookOpen,
      description: 'Share knowledge and expertise',
      fields: [
        { name: 'keyMessage', label: 'Key Educational Message', placeholder: 'Your main teaching point' },
        { name: 'educationTarget', label: 'Content Engagement Target', placeholder: '1,000 shares' },
      ],
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Target className="w-5 h-5" />
          Business Goals
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {goalSections.map((section) => {
          const Icon = section.icon;
          const isSelected = goals[section.id as keyof BrandGoals] as boolean;

          return (
            <div key={section.id} className="space-y-4">
              <FormField
                control={form.control}
                name={`goals.${section.id}`}
                render={({ field }) => (
                  <FormItem className="flex flex-row items-start space-x-3 space-y-0">
                    <FormControl>
                      <Checkbox
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                    <div className="space-y-1 leading-none">
                      <FormLabel className="flex items-center gap-2 text-base font-medium">
                        <Icon className="w-4 h-4" />
                        {section.title}
                      </FormLabel>
                      <p className="text-sm text-muted-foreground">
                        {section.description}
                      </p>
                    </div>
                  </FormItem>
                )}
              />

              {isSelected && (
                <div className="ml-6 space-y-3 border-l-2 border-gray-200 pl-4">
                  {section.fields.map((field) => (
                    <FormField
                      key={field.name}
                      control={form.control}
                      name={`goals.${field.name}`}
                      render={({ field: formField }) => (
                        <FormItem>
                          <FormLabel className="text-sm">{field.label}</FormLabel>
                          <FormControl>
                            <Input
                              placeholder={field.placeholder}
                              {...formField}
                              className="h-8"
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}