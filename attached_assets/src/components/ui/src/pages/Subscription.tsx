import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { CheckIcon, Star, ArrowLeft, Cpu, Zap, Gift } from "lucide-react";
import { Link } from "wouter";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import AIWidget from "@/components/grok-widget";
import agencyLogoPath from "@assets/agency_logo_1749083054761.png";
import { MetaPixelTracker } from "@/lib/meta-pixel";

const signupSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  phone: z.string().min(10, "Phone number must be at least 10 characters"),
});

type SignupForm = z.infer<typeof signupSchema>;

export default function Subscription() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);
  const [selectedPlan, setSelectedPlan] = useState<string | null>(null);
  const [showSignupForm, setShowSignupForm] = useState<string | null>(null);

  const form = useForm<SignupForm>({
    resolver: zodResolver(signupSchema),
    defaultValues: {
      email: "",
      password: "", 
      phone: "",
    },
  });

  useEffect(() => {
    // Get plan from URL parameters if coming from splash page
    const urlParams = new URLSearchParams(window.location.search);
    const planParam = urlParams.get('plan');
    if (planParam) {
      setSelectedPlan(planParam);
    }
  }, []);

  const plans = [
    {
      id: "starter",
      name: "starter",
      price: "$19.99/month",
      posts: "10 posts per 30 days",
      priceId: import.meta.env.VITE_STRIPE_PRICE_ID_STARTER || "price_1234567890starter",
    },
    {
      id: "growth",
      name: "growth",
      price: "$41.99/month", 
      posts: "20 posts per 30 days",
      priceId: import.meta.env.VITE_STRIPE_PRICE_ID_GROWTH || "price_1234567890growth",
      popular: true,
    },
    {
      id: "professional",
      name: "professional",
      price: "$99.99/month",
      posts: "30 posts per 30 days",
      priceId: import.meta.env.VITE_STRIPE_PRICE_ID_PROFESSIONAL || "price_1234567890professional",
    },
  ];

  const getFeatures = (planId: string) => {
    const baseFeatures = [
      "brand purpose creation",
      "social media scheduling", 
      "automated post creation",
      "automated posting",
      "post analytics",
      "content recommendation",
      "q&a assistant",
      "platform connections",
    ];
    
    if (planId === "professional") {
      return [
        ...baseFeatures,
        "veo 3.0 video generation", // Exclusive to Professional
      ];
    }
    
    return baseFeatures;
  };

  const handleSelectPlan = (planId: string) => {
    setShowSignupForm(planId);
    
    // Track plan selection for conversion optimisation
    const plan = plans.find(p => p.id === planId);
    if (plan) {
      MetaPixelTracker.trackConversionFunnel('subscription_plan_selected', {
        plan_name: plan.name,
        plan_price: plan.price,
        plan_posts: plan.posts
      });
    }
  };

  const handleSignupAndPayment = async (data: SignupForm, priceId: string, planId: string) => {
    try {
      setLoadingPlan(planId);
      
      // Track registration initiation
      MetaPixelTracker.trackConversionFunnel('registration_started', {
        plan_id: planId,
        email: data.email,
        phone: data.phone
      });
      
      // First create the user account
      await apiRequest("POST", "/api/auth/signup", data);
      
      // Track successful registration
      const plan = plans.find(p => p.id === planId);
      if (plan) {
        MetaPixelTracker.trackUserRegistration('subscription_form', plan.name);
        
        // Track lead generation
        MetaPixelTracker.trackLead('subscription_signup', plan.name === 'Professional' ? 197 : plan.name === 'Growth' ? 97 : 47);
      }
      
      // Then create checkout session with the new user
      const response = await apiRequest("POST", "/api/create-checkout-session", {
        priceId,
      });
      
      const checkoutData = await response.json();
      
      if (checkoutData.url) {
        // Track checkout initiation
        MetaPixelTracker.trackEvent('InitiateCheckout', {
          value: plan?.name === 'Professional' ? 197 : plan?.name === 'Growth' ? 97 : 47,
          currency: 'AUD',
          content_name: plan?.name + ' Subscription',
          content_category: 'subscription'
        });
        
        window.location.href = checkoutData.url;
      } else {
        throw new Error("No checkout URL received");
      }
    } catch (error: any) {
      console.error("Signup and payment error:", error);
      
      // Track registration/payment failure
      MetaPixelTracker.trackError('subscription_signup_failed', error.message, {
        plan_id: planId,
        step: 'payment_initiation'
      });
      
      toast({
        title: "Process Failed",
        description: error.message || "Failed to create account and process payment",
        variant: "destructive",
      });
    } finally {
      setLoadingPlan(null);
    }
  };

  const onSubmitSignup = (data: SignupForm) => {
    if (!showSignupForm) return;
    
    const plan = plans.find(p => p.id === showSignupForm);
    if (plan) {
      handleSignupAndPayment(data, plan.priceId, plan.id);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Navigation */}
      <nav className="sticky top-0 z-50 bg-white/95 backdrop-blur-md border-b border-border/40">
        <div className="container-atomiq">
          <div className="flex justify-between items-center h-20">
            <div className="flex items-center">
              <Link href="/" className="flex items-center">
                <ArrowLeft className="h-5 w-5 text-muted-foreground mr-3" />
                <img 
                  src={agencyLogoPath} 
                  alt="AiQ" 
                  className="h-12 w-auto"
                />
              </Link>
            </div>
            <div className="flex items-center space-x-6">
              <Link href="/redeem-certificate">
                <Button variant="outline" className="nav-link">
                  <Gift className="h-4 w-4 mr-2" />
                  Redeem Certificate
                </Button>
              </Link>
              <Link href="/login">
                <Button variant="ghost" className="nav-link">Sign In</Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>
      
      {/* Hero Section */}
      <section className="section-spacing bg-white">
        <div className="container-atomiq text-center">
          <div className="space-y-6 mb-16">
            <div className="inline-flex items-center px-4 py-2 bg-primary/10 rounded-full text-primary text-sm font-medium">
              <Zap className="h-4 w-4 mr-2" />
              Technology Intelligence Plans
            </div>
            <h1 className="text-4xl md:text-5xl font-bold">
              Choose Your <img src={agencyLogoPath} alt="AiQ" className="inline h-12 w-auto mx-2" /> Plan
            </h1>
            <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
              Select the perfect plan for your Queensland business. All plans include AI-powered content generation, smart scheduling, and platform connections.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6 max-w-4xl mx-auto">
            {plans.map((plan, index) => (
              <div 
                key={plan.id} 
                className={`pricing-card p-6 ${
                  plan.popular ? 'pricing-card-popular' : ''
                }`}
              >
                {plan.popular && (
                  <div className="absolute top-0 left-1/2 transform -translate-x-1/2 bg-gradient-atomiq text-white px-4 py-1 rounded-b-lg text-sm font-medium">
                    Most Popular
                  </div>
                )}
                
                <div className={`space-y-6 ${plan.popular ? 'pt-4' : ''}`}>
                  <div className="space-y-2">
                    <h3 className="text-2xl font-bold capitalize">{plan.name}</h3>
                    <div className="text-center">
                      <div className="text-3xl font-bold text-primary">{plan.price.split('/')[0]}</div>
                      <div className="text-sm text-muted-foreground">/month</div>
                    </div>
                    <p className="text-muted-foreground">{plan.posts}</p>
                  </div>
                  
                  <div className="space-y-4">
                    {getFeatures(plan.id).map((feature, featureIndex) => (
                      <div key={featureIndex} className="flex items-center space-x-3">
                        <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 ${
                          feature === "veo 3.0 video generation" 
                            ? "bg-gradient-to-r from-purple-600 to-indigo-600" 
                            : "bg-gradient-atomiq"
                        }`}>
                          <CheckIcon className="w-3 h-3 text-white" />
                        </div>
                        <span className={`text-sm text-left capitalize ${
                          feature === "veo 3.0 video generation" 
                            ? "font-semibold text-purple-800" 
                            : ""
                        }`}>
                          {feature}
                          {feature === "veo 3.0 video generation" && (
                            <span className="ml-2 text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded-full font-medium">
                              PRO EXCLUSIVE
                            </span>
                          )}
                        </span>
                      </div>
                    ))}
                  </div>

                  {showSignupForm === plan.id ? (
                    <div className="space-y-4 mt-6">
                      <form onSubmit={form.handleSubmit(onSubmitSignup)} className="space-y-4">
                        <div>
                          <Label htmlFor={`email-${plan.id}`} className="text-sm font-medium text-gray-700">Email</Label>
                          <Input
                            id={`email-${plan.id}`}
                            type="email"
                            {...form.register('email')}
                            className="mt-1"
                            placeholder="your@email.com"
                          />
                          {form.formState.errors.email && (
                            <p className="text-sm text-red-600 mt-1">{form.formState.errors.email.message}</p>
                          )}
                        </div>
                        
                        <div>
                          <Label htmlFor={`password-${plan.id}`} className="text-sm font-medium text-gray-700">Password</Label>
                          <Input
                            id={`password-${plan.id}`}
                            type="password"
                            {...form.register('password')}
                            className="mt-1"
                            placeholder="••••••••"
                          />
                          {form.formState.errors.password && (
                            <p className="text-sm text-red-600 mt-1">{form.formState.errors.password.message}</p>
                          )}
                        </div>
                        
                        <div>
                          <Label htmlFor={`phone-${plan.id}`} className="text-sm font-medium text-gray-700">Phone</Label>
                          <Input
                            id={`phone-${plan.id}`}
                            type="tel"
                            {...form.register('phone')}
                            className="mt-1"
                            placeholder="+15005550006"
                          />
                          {form.formState.errors.phone && (
                            <p className="text-sm text-red-600 mt-1">{form.formState.errors.phone.message}</p>
                          )}
                        </div>
                        
                        <Button 
                          type="submit"
                          className={`w-full text-lg py-6 ${
                            plan.popular 
                              ? 'btn-atomiq-primary'
                              : 'btn-atomiq-secondary'
                          } ${
                            loadingPlan === plan.id ? 'opacity-50 cursor-not-allowed' : ''
                          }`}
                          disabled={loadingPlan === plan.id}
                        >
                          {loadingPlan === plan.id ? (
                            <div className="flex items-center space-x-2">
                              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                              <span>Creating Account...</span>
                            </div>
                          ) : (
                            `Sign Up & Pay ${plan.price}`
                          )}
                        </Button>
                      </form>
                      
                      <Button 
                        variant="outline"
                        className="w-full"
                        onClick={() => setShowSignupForm(null)}
                      >
                        Back to Plans
                      </Button>
                    </div>
                  ) : (
                    <Button 
                      className={`w-full text-lg py-6 
                        transition-all duration-300 ease-in-out
                        hover:scale-105 hover:shadow-xl
                        transform-gpu will-change-transform
                        active:scale-95 active:transition-none
                        ${plan.popular 
                          ? 'bg-gradient-to-r from-blue-500 via-cyan-400 to-pink-400 text-white animate-enhanced-pulse hover:animate-none hover:from-blue-600 hover:via-cyan-500 hover:to-pink-500 shadow-lg shadow-pink-200/50' 
                          : 'btn-atomiq-secondary hover:bg-gray-100 dark:hover:bg-gray-700'
                        }`}
                      onClick={() => handleSelectPlan(plan.id)}
                    >
                      Select {plan.name}
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className="mt-16 space-y-8">
            <div className="grid md:grid-cols-3 gap-8 text-center">
              <div className="space-y-2">
                <div className="w-12 h-12 bg-gradient-atomiq rounded-xl flex items-center justify-center mx-auto">
                  <CheckIcon className="h-6 w-6 text-white" />
                </div>
                <h4 className="font-semibold">No Setup Fees</h4>
                <p className="text-sm text-muted-foreground">Start immediately with no hidden costs</p>
              </div>
              <div className="space-y-2">
                <div className="w-12 h-12 bg-gradient-atomiq rounded-xl flex items-center justify-center mx-auto">
                  <Star className="h-6 w-6 text-white" />
                </div>
                <h4 className="font-semibold">Cancel Anytime</h4>
                <p className="text-sm text-muted-foreground">Flexible subscription with no long-term commitment</p>
              </div>
              <div className="space-y-2">
                <div className="w-12 h-12 bg-gradient-atomiq rounded-xl flex items-center justify-center mx-auto">
                  <Zap className="h-6 w-6 text-white" />
                </div>
                <h4 className="font-semibold">AI-Powered</h4>
                <p className="text-sm text-muted-foreground">Advanced technology for intelligent automation</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Simple Footer */}
      <footer className="bg-card border-t">
        <div className="container-atomiq py-8">
          <div className="text-center space-y-4">
            <div className="flex flex-col sm:flex-row justify-center items-center gap-4 text-sm">
              <a 
                href="https://theagencyiq.ai/privacy-policy" 
                className="text-muted-foreground hover:text-primary transition-colors"
                target="_blank"
                rel="noopener noreferrer"
              >
                Privacy Policy
              </a>
              <span className="hidden sm:block text-muted-foreground">•</span>
              <a 
                href="https://theagencyiq.ai/terms-of-service" 
                className="text-muted-foreground hover:text-primary transition-colors"
                target="_blank"
                rel="noopener noreferrer"
              >
                Terms and Conditions
              </a>
            </div>
            <p className="text-muted-foreground text-sm">
              &copy; 2024 MacleodGlobal trading as The AgencyIQ. All rights reserved.
            </p>
          </div>
        </div>
      </footer>

      <AIWidget />
    </div>
  );
}
