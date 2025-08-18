import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";

interface ForgotPasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const forgotPasswordSchema = z.object({
  email: z.string().email("Invalid email address"),
  phone: z.string().min(10, "Valid phone number is required"),
});

type ForgotPasswordForm = z.infer<typeof forgotPasswordSchema>;

export default function ForgotPasswordModal({ isOpen, onClose }: ForgotPasswordModalProps) {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  const form = useForm<ForgotPasswordForm>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: {
      email: "",
      phone: "",
    },
  });

  const onSubmit = async (data: ForgotPasswordForm) => {
    try {
      setLoading(true);
      
      await apiRequest("POST", "/api/forgot-password", data);
      
      toast({
        title: "Reset Link Sent",
        description: "If an account exists with matching email and phone, a reset link has been sent to your email",
      });
      
      onClose();
    } catch (error: any) {
      console.error("Forgot password error:", error);
      toast({
        title: "Error",
        description: "Failed to process request",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="card-agencyiq max-w-md">
        <DialogHeader>
          <DialogTitle className="text-xl font-light text-foreground">Reset Password</DialogTitle>
        </DialogHeader>
        
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-sections">
          <div>
            <Label className="text-sm font-medium text-foreground lowercase">email address</Label>
            <Input
              type="email"
              placeholder="your@email.com"
              {...form.register('email')}
              className="mt-2"
            />
            {form.formState.errors.email && (
              <p className="text-sm text-destructive mt-1">{form.formState.errors.email.message}</p>
            )}
          </div>

          <div>
            <Label className="text-sm font-medium text-foreground lowercase">phone number</Label>
            <Input
              type="tel"
              placeholder="+61412345678"
              {...form.register('phone')}
              className="mt-2"
            />
            {form.formState.errors.phone && (
              <p className="text-sm text-destructive mt-1">{form.formState.errors.phone.message}</p>
            )}
          </div>
          
          <Button
            type="submit"
            className="w-full btn-secondary"
            disabled={loading}
          >
            {loading ? 'Sending...' : 'Send Reset Link'}
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}
