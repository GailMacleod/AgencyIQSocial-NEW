import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { XIcon } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";

interface User {
  id: number;
  email: string;
  phone: string;
  subscriptionPlan: string;
}

interface ProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  user?: User;
}

const profileSchema = z.object({
  phone: z.string().optional(),
  password: z.string().optional(),
});

type ProfileForm = z.infer<typeof profileSchema>;

export default function ProfileModal({ isOpen, onClose, user }: ProfileModalProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const form = useForm<ProfileForm>({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      phone: user?.phone || "",
      password: "",
    },
  });

  const updateProfileMutation = useMutation({
    mutationFn: (data: ProfileForm) => apiRequest("PUT", "/api/profile", data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      toast({
        title: "Profile Updated",
        description: "Your profile has been updated successfully",
      });
      onClose();
    },
    onError: (error: any) => {
      console.error("Profile update error:", error);
      toast({
        title: "Update Failed",
        description: "Failed to update profile",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: ProfileForm) => {
    // Only send fields that have values
    const updateData: any = {};
    if (data.phone && data.phone !== user?.phone) {
      updateData.phone = data.phone;
    }
    if (data.password && data.password.trim()) {
      updateData.password = data.password;
    }

    if (Object.keys(updateData).length === 0) {
      toast({
        title: "No Changes",
        description: "No changes to save",
      });
      return;
    }

    updateProfileMutation.mutate(updateData);
  };

  const getPlanDisplay = (plan: string) => {
    const planMap = {
      starter: "Starter Plan - A$19.99/month",
      growth: "Growth Plan - A$41.99/month", 
      professional: "Professional Plan - A$99.99/month",
    };
    return planMap[plan as keyof typeof planMap] || `${plan} Plan`;
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="card-agencyiq max-w-md">
        <DialogHeader>
          <DialogTitle className="text-xl font-light text-foreground">Edit Profile</DialogTitle>
        </DialogHeader>
        
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-sections">
          <div>
            <Label className="text-sm font-medium text-foreground">Email</Label>
            <Input
              type="email"
              value={user?.email || "demo@agencyiq.com"}
              className="mt-2 bg-muted"
              disabled
            />
          </div>
          
          <div>
            <Label className="text-sm font-medium text-foreground">Phone</Label>
            <Input
              type="tel"
              {...form.register('phone')}
              className="mt-2"
            />
          </div>
          
          <div>
            <Label className="text-sm font-medium text-foreground">Plan</Label>
            <Input
              type="text"
              value={getPlanDisplay(user?.subscriptionPlan || "growth")}
              className="mt-2 bg-muted"
              disabled
            />
          </div>
          
          <div>
            <Label className="text-sm font-medium text-foreground lowercase">new password</Label>
            <Input
              type="password"
              placeholder="leave blank to keep current password"
              {...form.register('password')}
              className="mt-2"
            />
          </div>
          
          <Button
            type="submit"
            className="w-full btn-secondary"
            disabled={updateProfileMutation.isPending}
          >
            {updateProfileMutation.isPending ? 'saving...' : 'save changes'}
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}
