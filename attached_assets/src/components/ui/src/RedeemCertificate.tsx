import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Gift, CheckCircle, AlertCircle } from "lucide-react";
import { MetaPixelTracker } from "@/lib/meta-pixel";

const certificateSchema = z.object({
  code: z.string().min(1, "Certificate code is required").max(50, "Code is too long"),
  email: z.string().email("Valid email is required"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  phone: z.string().optional(),
});

type CertificateForm = z.infer<typeof certificateSchema>;

export default function RedeemCertificate() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const form = useForm<CertificateForm>({
    resolver: zodResolver(certificateSchema),
    defaultValues: {
      code: "",
      email: "",
      password: "",
      phone: "",
    },
  });

  const redeemMutation = useMutation({
    mutationFn: (data: CertificateForm) => apiRequest("POST", "/api/redeem-gift-certificate", data),
    onSuccess: (data: any) => {
      // Track successful gift certificate redemption
      MetaPixelTracker.trackGiftCertificateRedeem(data.certificateCode || form.getValues('code'), data.plan);
      
      // Track as a conversion event
      MetaPixelTracker.trackEvent('Purchase', {
        value: data.plan === 'Professional' ? 197 : data.plan === 'Growth' ? 97 : 47,
        currency: 'AUD',
        content_name: `${data.plan} Plan (Gift Certificate)`,
        content_category: 'gift_certificate_redemption'
      });
      
      // Track conversion funnel completion
      MetaPixelTracker.trackConversionFunnel('gift_certificate_redeemed', {
        plan: data.plan,
        posts_available: data.user.remainingPosts,
        certificate_code: form.getValues('code')
      });
      
      toast({
        title: "Certificate Redeemed Successfully!",
        description: `Your account has been upgraded to ${data.plan} plan with ${data.user.remainingPosts} posts available.`,
      });
      
      // Invalidate user data to refresh subscription status
      queryClient.invalidateQueries({ queryKey: ["/api/user"] });
      
      // Redirect to schedule page to start using the upgraded plan
      setLocation("/schedule");
    },
    onError: (error: any) => {
      // Track redemption failure
      MetaPixelTracker.trackError('gift_certificate_redemption_failed', error.message, {
        certificate_code: form.getValues('code'),
        step: 'redemption_validation'
      });
      
      toast({
        title: "Redemption Failed",
        description: error.message || "Failed to redeem certificate. Please check your code and try again.",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: CertificateForm) => {
    redeemMutation.mutate(data);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto w-12 h-12 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center mb-4">
            <Gift className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <CardTitle className="text-2xl font-bold text-gray-900 dark:text-white">
            Redeem Gift Certificate
          </CardTitle>
          <CardDescription className="text-gray-600 dark:text-gray-400">
            Create your new account using a gift certificate
          </CardDescription>
        </CardHeader>

        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="code"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Certificate Code</FormLabel>
                    <FormControl>
                      <Input
                        {...field}
                        placeholder="PROF-TEST-XXXXXXXX"
                        className="text-center font-mono text-lg tracking-wider uppercase"
                        onChange={(e) => field.onChange(e.target.value.toUpperCase())}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Email Address</FormLabel>
                    <FormControl>
                      <Input
                        {...field}
                        type="email"
                        placeholder="your@email.com"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input
                        {...field}
                        type="password"
                        placeholder="Create a secure password"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="phone"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Phone Number (Optional)</FormLabel>
                    <FormControl>
                      <Input
                        {...field}
                        type="tel"
                        placeholder="+61 xxx xxx xxx"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button
                type="submit"
                className="w-full"
                disabled={redeemMutation.isPending}
              >
                {redeemMutation.isPending ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                    Redeeming Certificate...
                  </>
                ) : (
                  <>
                    <Gift className="w-4 h-4 mr-2" />
                    Redeem Certificate
                  </>
                )}
              </Button>
            </form>
          </Form>

          {/* Info sections */}
          <div className="mt-6 space-y-4">
            <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
              <div className="flex items-center space-x-2 text-green-800 dark:text-green-400">
                <CheckCircle className="w-4 h-4" />
                <span className="font-medium">What you'll get:</span>
              </div>
              <ul className="mt-2 text-sm text-green-700 dark:text-green-300 space-y-1">
                <li>• Instant account upgrade</li>
                <li>• Full access to all features</li>
                <li>• Increased post generation limits</li>
                <li>• Priority content scheduling</li>
              </ul>
            </div>

            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
              <div className="flex items-center space-x-2 text-blue-800 dark:text-blue-400">
                <AlertCircle className="w-4 h-4" />
                <span className="font-medium">Important:</span>
              </div>
              <p className="mt-2 text-sm text-blue-700 dark:text-blue-300">
                Gift certificates can only be used once. Make sure to enter the code exactly as provided.
              </p>
            </div>
          </div>

          <div className="mt-6 text-center">
            <Button
              variant="link"
              onClick={() => setLocation("/subscription")}
              className="text-sm text-gray-600 dark:text-gray-400"
            >
              Don't have a certificate? View subscription plans
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}