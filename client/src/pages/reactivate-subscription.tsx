import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle, AlertCircle, RefreshCw, Zap } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import agencyLogoPath from "@assets/agency_logo_1024x1024 (2)_1752385824604.png";

export default function ReactivateSubscription() {
  const { data: user } = useQuery({
    queryKey: ["/api/user"],
    retry: false,
  });

  const plans = [
    {
      name: "Starter",
      price: "$19.99",
      posts: "10 posts per 30 days",
      features: [
        "AI-powered content generation",
        "Facebook & Instagram posting",
        "Basic analytics",
        "Queensland business context"
      ]
    },
    {
      name: "Growth", 
      price: "$49.99",
      posts: "20 posts per 30 days",
      features: [
        "All Starter features",
        "LinkedIn & X (Twitter) posting",
        "Advanced scheduling",
        "Performance insights",
        "Brand purpose integration"
      ]
    },
    {
      name: "Professional",
      price: "$99.99", 
      posts: "30 posts per 30 days",
      popular: true,
      features: [
        "All Growth features",
        "YouTube video posting",
        "VEO 3.0 video generation",
        "Advanced analytics",
        "Priority support",
        "Custom branding"
      ]
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-md sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <img 
                src={agencyLogoPath} 
                alt="TheAgencyIQ" 
                className="h-10 w-auto"
              />
              <div>
                <h1 className="text-xl font-bold text-gray-900">TheAgencyIQ</h1>
                <p className="text-sm text-gray-500">Social Media Automation</p>
              </div>
            </div>
            <Badge variant="destructive" className="px-3 py-1">
              <AlertCircle className="w-4 h-4 mr-1" />
              Subscription Cancelled
            </Badge>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Welcome Back Section */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full mb-6">
            <RefreshCw className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Welcome Back, {(user as any)?.email?.split('@')[0] || 'Valued Customer'}!
          </h1>
          <p className="text-xl text-gray-600 mb-6 max-w-2xl mx-auto">
            Your subscription was cancelled, but we'd love to have you back. 
            Reactivate your plan to continue growing your Queensland business with AI-powered social media automation.
          </p>
          
          {/* Account Status Card */}
          <Card className="max-w-md mx-auto mb-8 border-orange-200 bg-orange-50">
            <CardContent className="p-6">
              <div className="flex items-center justify-center mb-4">
                <AlertCircle className="w-8 h-8 text-orange-600" />
              </div>
              <CardTitle className="text-center text-orange-800 mb-2">Account Status</CardTitle>
              <CardDescription className="text-center text-orange-700">
                Your account has limited access. Reactivate to restore full functionality including:
              </CardDescription>
              <ul className="mt-4 space-y-2 text-sm text-orange-700">
                <li className="flex items-center">
                  <CheckCircle className="w-4 h-4 mr-2 text-orange-600" />
                  AI content generation
                </li>
                <li className="flex items-center">
                  <CheckCircle className="w-4 h-4 mr-2 text-orange-600" />
                  Multi-platform posting
                </li>
                <li className="flex items-center">
                  <CheckCircle className="w-4 h-4 mr-2 text-orange-600" />
                  Advanced analytics
                </li>
              </ul>
            </CardContent>
          </Card>
        </div>

        {/* Pricing Plans */}
        <div className="mb-12">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-gray-900 mb-4">Choose Your Plan</h2>
            <p className="text-lg text-gray-600">
              Select the perfect plan for your Queensland business needs
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6 max-w-5xl mx-auto">
            {plans.map((plan, index) => (
              <Card 
                key={plan.name}
                className={`relative transition-all duration-300 hover:shadow-xl ${
                  plan.popular 
                    ? 'border-blue-500 shadow-lg ring-2 ring-blue-200' 
                    : 'hover:border-blue-300'
                }`}
              >
                {plan.popular && (
                  <div className="absolute -top-4 left-1/2 transform -translate-x-1/2">
                    <Badge className="bg-gradient-to-r from-blue-600 to-purple-600 text-white px-6 py-1">
                      <Zap className="w-4 h-4 mr-1" />
                      Most Popular
                    </Badge>
                  </div>
                )}
                
                <CardHeader className="text-center pb-4">
                  <CardTitle className="text-2xl font-bold text-gray-900">
                    {plan.name}
                  </CardTitle>
                  <div className="mt-4">
                    <span className="text-4xl font-bold text-gray-900">{plan.price}</span>
                    <span className="text-gray-500">/month</span>
                  </div>
                  <CardDescription className="text-lg font-semibold text-blue-600 mt-2">
                    {plan.posts}
                  </CardDescription>
                </CardHeader>
                
                <CardContent className="pt-0">
                  <ul className="space-y-3 mb-8">
                    {plan.features.map((feature, featureIndex) => (
                      <li key={featureIndex} className="flex items-start">
                        <CheckCircle className="w-5 h-5 text-green-500 mr-3 mt-0.5 flex-shrink-0" />
                        <span className="text-gray-700">{feature}</span>
                      </li>
                    ))}
                  </ul>
                  
                  <Link href="/subscription">
                    <Button 
                      className={`w-full py-3 text-lg font-semibold transition-all duration-300 ${
                        plan.popular
                          ? 'bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white shadow-lg'
                          : 'bg-gray-900 hover:bg-gray-800 text-white'
                      }`}
                    >
                      Reactivate {plan.name}
                    </Button>
                  </Link>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* Why Reactivate Section */}
        <div className="text-center">
          <Card className="max-w-4xl mx-auto bg-gradient-to-br from-blue-50 to-purple-50 border-blue-200">
            <CardContent className="p-8">
              <h3 className="text-2xl font-bold text-gray-900 mb-6">
                Why Reactivate Your TheAgencyIQ Subscription?
              </h3>
              <div className="grid md:grid-cols-3 gap-6">
                <div className="text-center">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-blue-100 rounded-full mb-4">
                    <Zap className="w-6 h-6 text-blue-600" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">AI-Powered Content</h4>
                  <p className="text-gray-600 text-sm">
                    Generate engaging posts tailored for Queensland businesses using advanced AI
                  </p>
                </div>
                <div className="text-center">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-purple-100 rounded-full mb-4">
                    <RefreshCw className="w-6 h-6 text-purple-600" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Automated Posting</h4>
                  <p className="text-gray-600 text-sm">
                    Schedule and publish across Facebook, Instagram, LinkedIn, X, and YouTube
                  </p>
                </div>
                <div className="text-center">
                  <div className="inline-flex items-center justify-center w-12 h-12 bg-green-100 rounded-full mb-4">
                    <CheckCircle className="w-6 h-6 text-green-600" />
                  </div>
                  <h4 className="font-semibold text-gray-900 mb-2">Proven Results</h4>
                  <p className="text-gray-600 text-sm">
                    Join hundreds of Queensland SMEs growing their online presence
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}