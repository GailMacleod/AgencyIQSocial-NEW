import { useState } from "react";
import { Link, useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";

const signupSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  phone: z.string().min(10, "Phone number must be at least 10 characters"),
});

type SignupForm = z.infer<typeof signupSchema>;

export default function Signup() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  const form = useForm<SignupForm>({
    resolver: zodResolver(signupSchema),
    defaultValues: {
      email: "",
      password: "", 
      phone: "",
    },
  });

  const onSubmit = async (data: SignupForm) => {
    try {
      setLoading(true);
      
      // Create user directly without verification
      const response = await apiRequest("POST", "/api/auth/signup", data);
      
      toast({
        title: "Account Created",
        description: "Your account has been created successfully",
      });
      
      setLocation("/subscription");
    } catch (error: any) {
      console.error("Signup error:", error);
      toast({
        title: "Signup Failed",
        description: error.message || "Failed to create account",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Navigation */}
      <nav className="sticky top-0 z-50 bg-white/95 backdrop-blur-md border-b border-border/40">
        <div className="container-atomiq">
          <div className="flex justify-between items-center h-20">
            <div className="flex items-center">
              <Link href="/subscription" className="flex items-center">
                <ArrowLeft className="h-5 w-5 text-muted-foreground mr-3" />
                <img 
                  src="/attached_assets/agency_logo_1749083054761.png" 
                  alt="AiQ" 
                  className="h-12 w-auto"
                />
              </Link>
            </div>
            <div className="flex items-center space-x-6">
              <Link href="/login">
                <Button variant="ghost" className="nav-link">Sign In</Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>
      
      <section className="section-spacing bg-white">
        <div className="container-atomiq">
          <div className="max-w-md mx-auto">
            <div className="text-center mb-8">
              <h1 className="text-3xl font-bold text-gray-900 mb-4">
                Create Your Account
              </h1>
              <p className="text-lg text-gray-600">
                Join thousands of businesses automating their social media
              </p>
            </div>
            
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <div className="space-y-4">
                <div>
                  <Label htmlFor="email" className="text-sm font-medium text-gray-700">Email</Label>
                  <Input
                    id="email"
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
                  <Label htmlFor="password" className="text-sm font-medium text-gray-700">Password</Label>
                  <Input
                    id="password"
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
                  <Label htmlFor="phone" className="text-sm font-medium text-gray-700">Phone</Label>
                  <Input
                    id="phone"
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
                  disabled={loading}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 text-lg font-medium"
                >
                  {loading ? "Creating Account..." : "Create Account"}
                </Button>
              </div>
            </form>
            
            <div className="mt-6 text-center">
              <p className="text-sm text-gray-600">
                Already have an account?{' '}
                <Link href="/login" className="text-blue-600 hover:text-blue-700 font-medium">
                  Sign in
                </Link>
              </p>
            </div>
            
            <div className="mt-8 text-center">
              <p className="text-xs text-gray-500">
                MacleodGlobal T/A The AgencyIQ
              </p>
              <div className="flex justify-center space-x-4 mt-2">
                <Link href="#" className="text-xs text-gray-500 hover:text-gray-700">Privacy Policy</Link>
                <Link href="#" className="text-xs text-gray-500 hover:text-gray-700">Terms of Service</Link>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}