import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import Header from "@/components/header";
import Footer from "@/components/footer";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";

const resetPasswordSchema = z.object({
  password: z.string().min(8, "Password must be at least 8 characters"),
  confirmPassword: z.string().min(8, "Password must be at least 8 characters"),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

type ResetPasswordForm = z.infer<typeof resetPasswordSchema>;

export default function ResetPassword() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState<string>("");
  const [email, setEmail] = useState<string>("");
  const [validToken, setValidToken] = useState<boolean | null>(null);

  const form = useForm<ResetPasswordForm>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: {
      password: "",
      confirmPassword: "",
    },
  });

  // Extract token and email from URL parameters
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const tokenParam = urlParams.get('token');
    const emailParam = urlParams.get('email');
    
    if (tokenParam && emailParam) {
      setToken(tokenParam);
      setEmail(decodeURIComponent(emailParam));
      
      // Validate token
      validateToken(tokenParam, emailParam);
    } else {
      setValidToken(false);
      toast({
        title: "Invalid Reset Link",
        description: "The reset link is invalid or expired",
        variant: "destructive",
      });
    }
  }, [toast]);

  const validateToken = async (token: string, email: string) => {
    try {
      await apiRequest("POST", "/api/validate-reset-token", { token, email });
      setValidToken(true);
    } catch (error: any) {
      setValidToken(false);
      toast({
        title: "Invalid Reset Link",
        description: error.message || "The reset link is invalid or expired",
        variant: "destructive",
      });
    }
  };

  const onSubmit = async (data: ResetPasswordForm) => {
    if (!validToken || !token || !email) {
      toast({
        title: "Error",
        description: "Invalid reset token",
        variant: "destructive",
      });
      return;
    }

    try {
      setLoading(true);
      
      await apiRequest("POST", "/api/reset-password", {
        token,
        email,
        password: data.password,
      });
      
      toast({
        title: "Password Reset Successful",
        description: "Your password has been updated. You can now log in.",
      });
      
      setLocation("/login");
    } catch (error: any) {
      console.error("Reset password error:", error);
      toast({
        title: "Reset Failed",
        description: error.message || "Failed to reset password",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  if (validToken === null) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        <Header showLogin />
        <div className="flex-1 flex items-center justify-center px-4">
          <Card className="card-agencyiq max-w-md w-full">
            <CardContent className="p-8">
              <div className="text-center">
                <p className="text-foreground">Validating reset link...</p>
              </div>
            </CardContent>
          </Card>
        </div>
        <Footer />
      </div>
    );
  }

  if (validToken === false) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        <Header showLogin />
        <div className="flex-1 flex items-center justify-center px-4">
          <Card className="card-agencyiq max-w-md w-full">
            <CardContent className="p-8">
              <div className="text-center space-y-4">
                <h2 className="text-xl font-light text-foreground lowercase">invalid reset link</h2>
                <p className="text-muted-foreground">
                  The password reset link is invalid or has expired. Please request a new one.
                </p>
                <Button 
                  onClick={() => setLocation("/login")}
                  className="btn-secondary"
                >
                  back to login
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
        <Footer />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Header showLogin />
      
      <div className="flex-1 flex items-center justify-center px-4">
        <Card className="card-agencyiq max-w-md w-full">
          <CardContent className="p-8">
            <div className="text-center mb-8">
              <h2 className="text-xl font-light text-foreground lowercase">reset password</h2>
              <p className="text-sm text-muted-foreground mt-2 lowercase">
                enter your new password for {email}
              </p>
            </div>
            
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-sections">
              <div>
                <Label className="text-sm font-medium text-foreground lowercase">new password</Label>
                <Input
                  type="password"
                  {...form.register('password')}
                  className="mt-2"
                  placeholder="Enter new password"
                />
                {form.formState.errors.password && (
                  <p className="text-sm text-destructive mt-1">{form.formState.errors.password.message}</p>
                )}
              </div>
              
              <div>
                <Label className="text-sm font-medium text-foreground lowercase">confirm password</Label>
                <Input
                  type="password"
                  {...form.register('confirmPassword')}
                  className="mt-2"
                  placeholder="Confirm new password"
                />
                {form.formState.errors.confirmPassword && (
                  <p className="text-sm text-destructive mt-1">{form.formState.errors.confirmPassword.message}</p>
                )}
              </div>
              
              <Button
                type="submit"
                className="w-full btn-secondary"
                disabled={loading}
              >
                {loading ? 'updating password...' : 'update password'}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>

      <Footer />
    </div>
  );
}