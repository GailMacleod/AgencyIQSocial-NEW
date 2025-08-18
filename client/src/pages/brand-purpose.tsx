import { useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Upload, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { apiRequest } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";
import { useState, useEffect } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import MasterHeader from "@/components/master-header";
import MasterFooter from "@/components/master-footer";
import BackButton from "@/components/back-button";
import { Bot, Lightbulb } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import OnboardingWizard from "@/components/onboarding/OnboardingWizard";

const brandPurposeSchema = z.object({
  brandName: z.string().min(2, "Brand name must be at least 2 characters").max(600, "Brand name must be 600 characters or less"),
  productsServices: z.string().min(10, "Products/services description must be at least 10 characters").max(600, "Products/services description must be 600 characters or less"),
  corePurpose: z.string().min(10, "Core purpose must be at least 10 characters").max(600, "Core purpose must be 600 characters or less"),
  audience: z.string().min(10, "Ideal audience must be at least 10 characters").max(600, "Ideal audience must be 600 characters or less"),
  jobToBeDone: z.string().min(10, "Job to be done must be at least 10 characters").max(600, "Job to be done must be 600 characters or less"),
  motivations: z.string().min(10, "Audience motivations must be at least 10 characters").max(600, "Audience motivations must be 600 characters or less"),
  painPoints: z.string().min(10, "Pain points must be at least 10 characters").max(600, "Pain points must be 600 characters or less"),
  goals: z.object({
    driveTraffic: z.boolean().default(false),
    websiteUrl: z.string().optional(),
    trafficTarget: z.string().optional(),
    buildBrand: z.boolean().default(false),
    followerTarget: z.string().optional(),
    reachTarget: z.string().optional(),
    makeSales: z.boolean().default(false),
    salesUrl: z.string().optional(),
    salesTarget: z.string().optional(),
    conversionTarget: z.string().optional(),
    generateLeads: z.boolean().default(false),
    leadTarget: z.string().optional(),
    engagementTarget: z.string().optional(),
    informEducate: z.boolean().default(false),
    keyMessage: z.string().optional(),
    educationTarget: z.string().optional(),
  }),
  contactDetails: z.object({
    email: z.string().email("Invalid email").optional().or(z.literal("")),
    phone: z.string().optional(),
  }),
});

type BrandPurposeForm = z.infer<typeof brandPurposeSchema>;

export default function BrandPurpose() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [logoFile, setLogoFile] = useState<File | null>(null);
  const [logoPreview, setLogoPreview] = useState<string | null>(null);
  const [isExistingData, setIsExistingData] = useState(false);
  const [guidance, setGuidance] = useState<string>("");
  const [showGuidance, setShowGuidance] = useState(false);
  const [isGeneratingGuidance, setIsGeneratingGuidance] = useState(false);

  // Load existing brand purpose data
  const { data: existingBrandPurpose, isLoading: isLoadingBrandPurpose } = useQuery({
    queryKey: ["/api/brand-purpose"],
    retry: false,
    staleTime: 0,
  });

  // Check if logo exists and set preview
  useEffect(() => {
    const checkLogo = async () => {
      try {
        const response = await fetch('/uploads/logo.png');
        if (response.ok) {
          setLogoPreview('/uploads/logo.png');
          console.log('Existing logo loaded from server');
        }
      } catch (error) {
        console.log('No existing logo found');
      }
    };
    checkLogo();
  }, []);

  const form = useForm<BrandPurposeForm>({
    resolver: zodResolver(brandPurposeSchema),
    defaultValues: {
      brandName: "",
      productsServices: "",
      corePurpose: "",
      audience: "",
      jobToBeDone: "",
      motivations: "",
      painPoints: "",
      goals: {
        driveTraffic: false,
        websiteUrl: "",
        trafficTarget: "",
        buildBrand: false,
        followerTarget: "",
        reachTarget: "",
        makeSales: false,
        salesUrl: "",
        salesTarget: "",
        conversionTarget: "",
        generateLeads: false,
        leadTarget: "",
        engagementTarget: "",
        informEducate: false,
        keyMessage: "",
        educationTarget: "",
      },
      contactDetails: {
        email: "",
        phone: "",
      },
    },
  });

  // Load existing data into form when available
  useEffect(() => {
    if (existingBrandPurpose && typeof existingBrandPurpose === 'object') {
      setIsExistingData(true);
      console.log('Loading existing brand purpose data:', existingBrandPurpose);
      
      // Populate form with existing data for editing
      const brandData = existingBrandPurpose as any;
      form.reset({
        brandName: brandData.brandName || "",
        productsServices: brandData.productsServices || "",
        corePurpose: brandData.corePurpose || "",
        audience: brandData.audience || "",
        jobToBeDone: brandData.jobToBeDone || "",
        motivations: brandData.motivations || "",
        painPoints: brandData.painPoints || "",
        goals: {
          driveTraffic: brandData.goals?.driveTraffic || false,
          websiteUrl: brandData.goals?.websiteUrl || "",
          trafficTarget: brandData.goals?.trafficTarget || "",
          buildBrand: brandData.goals?.buildBrand || false,
          followerTarget: brandData.goals?.followerTarget || "",
          reachTarget: brandData.goals?.reachTarget || "",
          makeSales: brandData.goals?.makeSales || false,
          salesUrl: brandData.goals?.salesUrl || "",
          salesTarget: brandData.goals?.salesTarget || "",
          conversionTarget: brandData.goals?.conversionTarget || "",
          generateLeads: brandData.goals?.generateLeads || false,
          leadTarget: brandData.goals?.leadTarget || "",
          engagementTarget: brandData.goals?.engagementTarget || "",
          informEducate: brandData.goals?.informEducate || false,
          keyMessage: brandData.goals?.keyMessage || "",
          educationTarget: brandData.goals?.educationTarget || "",
        },
        contactDetails: {
          email: brandData.contactDetails?.email || "",
          phone: brandData.contactDetails?.phone || "",
        },
      });
      
      
      // Set logo preview if exists
      if (brandData.logoUrl) {
        setLogoPreview(brandData.logoUrl);
      }
      
      console.log('Form populated with brand data successfully');
    }
  }, [existingBrandPurpose, form]);

  // Watch form values to trigger Grok API waterfall content generation
  const brandName = form.watch("brandName");
  const productsServices = form.watch("productsServices");
  const corePurpose = form.watch("corePurpose");

  // Grok API waterfall content generation after first three fields
  useEffect(() => {
    // Trigger waterfall generation when first three fields have sufficient content
    if (brandName && brandName.length >= 2 && 
        productsServices && productsServices.length >= 10 && 
        corePurpose && corePurpose.length >= 10 &&
        !isGeneratingGuidance && !showGuidance && !isExistingData) {
      
      console.log('Triggering Grok API waterfall content generation...');
      setIsGeneratingGuidance(true);
      
      // Generate strategic guidance using AI analysis
      guidanceMutation.mutate({
        brandName,
        productsServices,
        corePurpose
      });
    }
  }, [brandName, productsServices, corePurpose, isGeneratingGuidance, showGuidance, isExistingData]);

  // Auto-save for better user experience
  const autoSaveMutation = useMutation({
    mutationFn: async (formData: Partial<BrandPurposeForm>) => {
      if (!formData.brandName || formData.brandName.length < 2) return null;
      
      try {
        const response = await apiRequest("POST", "/api/brand-purpose/autosave", formData);
        return response; // apiRequest already returns parsed JSON
      } catch (error) {
        console.error("Auto-save failed:", error);
        return null;
      }
    },
    onError: () => {},
    onSuccess: () => {
      console.log("Form auto-saved");
    },
    retry: false,
  });

  // Save brand purpose mutation with proper error handling
  const saveBrandPurposeMutation = useMutation({
    mutationFn: async (formData: BrandPurposeForm) => {
      try {
        const response = await apiRequest("POST", "/api/brand-purpose", formData);
        return response; // apiRequest already returns parsed JSON
      } catch (error) {
        console.error("Save brand purpose failed:", error);
        throw error;
      }
    },
    onSuccess: () => {
      toast({
        title: isExistingData ? "Brand Purpose Updated" : "Brand Purpose Saved",
        description: isExistingData ? "Your brand purpose has been updated and will inform your content schedule" : "Your brand purpose has been saved and will inform your content schedule",
      });
      setLocation("/schedule");
    },
    onError: (error: any) => {
      console.error("Brand purpose save error:", error);
      toast({
        title: "Save Failed",
        description: error.message || "Failed to save brand purpose",
        variant: "destructive",
      });
    },
  });

  // Generate guidance mutation with proper error handling
  const guidanceMutation = useMutation({
    mutationFn: async (formData: Partial<BrandPurposeForm>) => {
      try {
        const response = await apiRequest("POST", "/api/generate-guidance", {
          brandName: formData.brandName,
          productsServices: formData.productsServices,
          corePurpose: formData.corePurpose,
          audience: formData.audience,
          jobToBeDone: formData.jobToBeDone,
          motivations: formData.motivations,
          painPoints: formData.painPoints
        });
        return response.guidance;
      } catch (error) {
        console.error("Guidance API request failed:", error);
        return null;
      }
    },
    onSuccess: (guidance) => {
      if (guidance) {
        setGuidance(guidance);
        setShowGuidance(true);
      }
    },
    onError: (error) => {
      console.error("Failed to generate guidance:", error);
      // Silently fail guidance generation
    },
    onSettled: () => {
      setIsGeneratingGuidance(false);
    },
  });

  // Manual guidance generation on demand
  const generateGuidanceManually = () => {
    const formData = form.getValues();
    if (formData.brandName && formData.productsServices && formData.corePurpose) {
      setIsGeneratingGuidance(true);
      guidanceMutation.mutate(formData);
    }
  };

  // AI-powered autofill for remaining fields
  const [aiSuggestions, setAiSuggestions] = useState<{
    audience?: string;
    jobToBeDone?: string;
    motivations?: string;
    painPoints?: string;
  }>({});

  // Generate smart field suggestions when guidance is received
  useEffect(() => {
    if (guidance && showGuidance && brandName && productsServices && corePurpose) {
      // Extract AI-powered suggestions from your little helper analysis
      const generateSmartSuggestions = () => {
        const suggestions: any = {};
        
        // Audience suggestions based on brand analysis
        if (!form.getValues('audience') || form.getValues('audience').length < 20) {
          if (brandName.toLowerCase().includes('agency')) {
            suggestions.audience = "Queensland SMEs (5-50 employees), $200K-$2M revenue, time-poor business owners needing professional marketing presence, located in Brisbane, Gold Coast, and regional centers";
          } else {
            suggestions.audience = "Queensland small business owners, 30-55 years old, $100K-$2M annual revenue, digitally overwhelmed, seeking automation and professional growth";
          }
        }

        // Job-to-be-Done suggestions using AI analysis
        if (!form.getValues('jobToBeDone') || form.getValues('jobToBeDone').length < 20) {
          suggestions.jobToBeDone = "Functional: Maintain consistent professional marketing presence. Emotional: Feel confident about business visibility and growth. Social: Be seen as a credible, established business in the community";
        }

        // Motivations based on value proposition analysis
        if (!form.getValues('motivations') || form.getValues('motivations').length < 20) {
          suggestions.motivations = "Business growth aspirations, desire for professional credibility, need for time efficiency, fear of being left behind by competitors, wanting to focus on core business rather than marketing";
        }

        // Pain points extracted from core purpose
        if (!form.getValues('painPoints') || form.getValues('painPoints').length < 20) {
          suggestions.painPoints = "Invisible online presence, inconsistent marketing efforts, lack of time for social media, feeling overwhelmed by digital marketing complexity, losing customers to more visible competitors";
        }

        setAiSuggestions(suggestions);
      };

      generateSmartSuggestions();
    }
  }, [guidance, showGuidance, brandName, productsServices, corePurpose]);

  // Apply AI suggestion to field
  const applySuggestion = (field: string, suggestion: string) => {
    form.setValue(field as any, suggestion);
    toast({
      title: "AI Suggestion Applied",
      description: `AI-generated content added to ${field.replace(/([A-Z])/g, ' $1').toLowerCase()}`,
    });
  };

  // Form validation helper
  const validateFormData = (data: BrandPurposeForm) => {
    const requiredFields = [
      { field: 'brandName', name: 'Brand Name' },
      { field: 'productsServices', name: 'Products/Services' },
      { field: 'corePurpose', name: 'Core Purpose' },
      { field: 'audience', name: 'Ideal Audience' },
      { field: 'jobToBeDone', name: 'Job to be Done' },
      { field: 'motivations', name: 'Audience Motivations' },
      { field: 'painPoints', name: 'Pain Points' }
    ];

    const missingFields = requiredFields.filter(
      ({ field }) => !data[field as keyof BrandPurposeForm] || 
      (data[field as keyof BrandPurposeForm] as string).length < 10
    );

    return {
      isValid: missingFields.length === 0,
      missingFields: missingFields.map(f => f.name)
    };
  };

  const onSubmit = async (data: BrandPurposeForm) => {
    try {
      setLoading(true);
      
      // Validate form completeness
      const validation = validateFormData(data);
      if (!validation.isValid) {
        toast({
          title: "Incomplete Form",
          description: `Please complete: ${validation.missingFields.join(', ')}`,
          variant: "destructive",
        });
        return;
      }
      
      // Upload logo if provided
      let logoUrl = "";
      if (logoFile) {
        const formData = new FormData();
        formData.append('logo', logoFile);
        
        const logoResponse = await apiRequest("POST", "/api/upload-logo", formData);
        const logoData = await logoResponse.json();
        logoUrl = logoData.logoUrl;
      }
      
      const brandData = {
        ...data,
        logoUrl,
      };
      
      // Use the save mutation for proper error handling
      saveBrandPurposeMutation.mutate(brandData);
    } catch (error: any) {
      console.error("Brand purpose error:", error);
      toast({
        title: "Brand Purpose Failed",
        description: error.message || "Failed to save brand purpose",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleLogoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      console.log('File selected:', file.name, file.size, file.type);
      
      // Check file size (max 5MB)
      if (file.size > 5 * 1024 * 1024) {
        console.log('File rejected: too large', file.size);
        toast({
          title: "File Too Large",
          description: "Logo must be under 5MB",
          variant: "destructive",
        });
        return;
      }
      
      // Check file format
      if (!file.type.match(/^image\/(png|jpeg|jpg|webp)$/)) {
        console.log('File rejected: invalid format', file.type);
        toast({
          title: "Invalid Format",
          description: "Logo must be PNG, JPG, or WEBP format",
          variant: "destructive",
        });
        return;
      }
      
      // Upload file to server
      const formData = new FormData();
      formData.append('logo', file);
      
      try {
        // Set auth token for upload
        localStorage.setItem('token', 'valid-token');
        
        const response = await fetch('/api/upload-logo', {
          method: 'POST',
          headers: {
            'Authorization': localStorage.getItem('token') || '',
          },
          body: formData,
        });
        
        if (response.ok) {
          const responseData = await response.json();
          const url = URL.createObjectURL(file);
          setLogoFile(file);
          setLogoPreview(url);
          
          console.log('Logo uploaded successfully:', file.name, file.size);
          console.log('Server response:', responseData);
          console.log('Preview URL set:', url);
          
          // Force re-render
          setTimeout(() => {
            setLogoPreview(url);
          }, 100);
          
          toast({
            title: "Logo Uploaded",
            description: `Logo "${file.name}" uploaded successfully and preview updated.`,
          });
        } else {
          console.log('Upload failed:', response.status);
          toast({
            title: "Upload Failed",
            description: "Failed to upload logo. Please try again.",
            variant: "destructive",
          });
        }
      } catch (error) {
        console.log('Upload error:', error);
        toast({
          title: "Upload Error",
          description: "An error occurred while uploading the logo.",
          variant: "destructive",
        });
      }
    }
  };

  const handleDeleteLogo = () => {
    setLogoFile(null);
    if (logoPreview) {
      URL.revokeObjectURL(logoPreview);
      setLogoPreview(null);
    }
    // Clear the file input
    const fileInput = document.getElementById('logo') as HTMLInputElement;
    if (fileInput) {
      fileInput.value = '';
    }
  };

  return (
    <div className="min-h-screen" style={{ backgroundColor: '#f5f5f5' }}>
      <MasterHeader showUserMenu={true} />
      
      <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="mb-6">
          <BackButton to="/schedule" label="Back to Schedule" />
        </div>
        
        <div className="text-center mb-8">
          <p className="text-sm text-gray-600">step 2 of 3</p>
          <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
            <div className="bg-blue-600 h-2 rounded-full w-2/3"></div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow-md p-8">
              <h2 className="text-2xl font-normal text-center mb-8 bg-[#2563eb] text-[#ffffff]">
                {isExistingData ? 'Update your brand purpose' : 'Create your brand purpose'}
              </h2>
          
              <div className="space-y-4">
                {showGuidance && guidance && (
                  <Card className="bg-blue-50 border-blue-200">
                    <CardContent className="p-6">
                      <div className="flex items-start space-x-3">
                        <Bot className="w-5 h-5 text-blue-600 mt-0.5 flex-shrink-0" />
                        <div>
                          <h3 className="font-semibold text-blue-900 mb-2">AI Strategy Guidance</h3>
                          <div className="text-sm text-blue-800 whitespace-pre-wrap">{guidance}</div>
                          <Button 
                            variant="outline" 
                            size="sm" 
                            className="mt-3"
                            onClick={() => setShowGuidance(false)}
                          >
                            Dismiss
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}
                
                {/* AI Suggestions Section */}
                {Object.keys(aiSuggestions).length > 0 && (
                  <Card className="bg-green-50 border-green-200">
                    <CardContent className="p-6">
                      <div className="flex items-start space-x-3">
                        <Lightbulb className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" />
                        <div className="flex-1">
                          <h3 className="font-semibold text-green-900 mb-3">Smart Field Suggestions</h3>
                          <div className="space-y-3">
                            {Object.entries(aiSuggestions).map(([field, suggestion]) => (
                              <div key={field} className="bg-white p-4 rounded-lg border border-green-200">
                                <div className="flex justify-between items-start">
                                  <div className="flex-1">
                                    <div className="font-medium text-green-900 mb-1">
                                      {field.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                                    </div>
                                    <div className="text-sm text-green-700 mb-2">{suggestion}</div>
                                  </div>
                                  <Button 
                                    variant="outline" 
                                    size="sm"
                                    onClick={() => applySuggestion(field, suggestion)}
                                    className="ml-2"
                                  >
                                    Apply
                                  </Button>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </div>
          
          {isExistingData && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
              <div className="flex items-center">
                <div className="w-4 h-4 rounded-full bg-blue-500 mr-2"></div>
                <p className="text-sm text-blue-800">
                  Your brand purpose is already saved to your profile. You can update any information below.
                </p>
              </div>
            </div>
          )}



          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            {/* Brand Name */}
            <div>
              <Label htmlFor="brandName" className="text-sm font-medium text-gray-700">What's your brand name?</Label>
              <div className="relative group">
                <Input
                  id="brandName"
                  {...form.register('brandName')}
                  placeholder="The AgencyIQ"
                  className="mt-1"
                  autoComplete="organisation"
                />
                <div className="absolute inset-x-0 top-full mt-1 bg-purple-50 border border-purple-200 rounded-lg p-3 opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-10">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-purple-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-purple-900 mb-1">your little helper:</p>
                      <p className="text-xs text-purple-800">Your brand name should connect to your value proposition and target customer segment. Strong names communicate what you do and who you serve.</p>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between mt-2">
                <div className="flex items-center">
                  {(() => {
                    const brandName = form.watch('brandName') || '';
                    return brandName && brandName.length > 2 && (
                      <div className="flex items-center">
                        {brandName.length > 8 && (brandName.toLowerCase().includes('agency') || brandName.toLowerCase().includes('solutions') || brandName.toLowerCase().includes('group') || brandName.toLowerCase().includes('co')) ? (
                          <div className="flex items-center text-sm font-medium text-green-600 bg-green-50 px-2 py-1 rounded-md border border-green-200">
                            <div className="w-3 h-3 bg-green-600 rounded-full mr-2"></div>
                            Strong
                          </div>
                        ) : brandName.length > 5 ? (
                          <div className="flex items-center text-sm font-medium text-yellow-600 bg-yellow-50 px-2 py-1 rounded-md border border-yellow-200">
                            <div className="w-3 h-3 bg-yellow-600 rounded-full mr-2"></div>
                            Moderate
                          </div>
                        ) : (
                          <div className="flex items-center text-sm font-medium text-red-600 bg-red-50 px-2 py-1 rounded-md border border-red-200">
                            <div className="w-3 h-3 bg-red-600 rounded-full mr-2"></div>
                            Weak
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>
                {(() => {
                  const brandName = form.watch('brandName') || '';
                  return brandName && (
                    <div className={`text-xs ${brandName.length > 600 ? 'text-red-600 font-medium' : brandName.length > 540 ? 'text-yellow-600' : 'text-gray-500'}`}>
                      {brandName.length || 0}/600
                    </div>
                  );
                })()}
              </div>
              {form.formState.errors.brandName && (
                <p className="text-sm text-red-600 mt-1">{form.formState.errors.brandName.message}</p>
              )}
            </div>

            {/* Products/Services */}
            <div>
              <Label htmlFor="productsServices" className="text-sm font-medium text-gray-700">What products or services does your brand offer?</Label>
              <div className="relative group">
                <Textarea
                  id="productsServices"
                  {...form.register('productsServices')}
                  placeholder="Value proposition: You're invisible, that sucks. AgencyIQ gives you a beacon that's always on. The pain: You're invisible, and silence is killing your growth. The gain: You show up. Week in, week out. Professionally. Strategically. Automatically. Starter Subscription, 10 posts + 2 Free: $19.99/30 days Growth Subscription, 25 posts + 2 Free: $41.99/30 days Professional Subscription, 45 posts + 2 Free: $99.99/30 days"
                  className="mt-1 resize-none"
                  rows={3}
                  autoComplete="off"
                />
                <div className="absolute inset-x-0 top-full mt-1 bg-purple-50 border border-purple-200 rounded-lg p-3 opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-10">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-purple-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-purple-900 mb-1">your little helper:</p>
                      <p className="text-xs text-purple-800">Define your value proposition - what specific gain do you create or pain do you relieve? Include pricing and packages for clarity.</p>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between mt-2">
                <div className="flex items-center">
                  {(() => {
                    const productsServices = form.watch('productsServices') || '';
                    return productsServices && productsServices.length > 20 && (
                      <div className="flex items-center">
                        {productsServices.length > 100 && (productsServices.toLowerCase().includes('pain') || productsServices.toLowerCase().includes('gain') || productsServices.toLowerCase().includes('value') || productsServices.toLowerCase().includes('$')) ? (
                          <div className="flex items-center text-sm font-medium text-green-600 bg-green-50 px-2 py-1 rounded-md border border-green-200">
                            <div className="w-3 h-3 bg-green-600 rounded-full mr-2"></div>
                            Strong
                          </div>
                        ) : productsServices.length > 50 ? (
                          <div className="flex items-center text-sm font-medium text-yellow-600 bg-yellow-50 px-2 py-1 rounded-md border border-yellow-200">
                            <div className="w-3 h-3 bg-yellow-600 rounded-full mr-2"></div>
                            Moderate
                          </div>
                        ) : (
                          <div className="flex items-center text-sm font-medium text-red-600 bg-red-50 px-2 py-1 rounded-md border border-red-200">
                            <div className="w-3 h-3 bg-red-600 rounded-full mr-2"></div>
                            Weak
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>
                {(() => {
                  const productsServices = form.watch('productsServices') || '';
                  return productsServices && (
                    <div className={`text-xs ${productsServices.length > 600 ? 'text-red-600 font-medium' : productsServices.length > 540 ? 'text-yellow-600' : 'text-gray-500'}`}>
                      {productsServices.length || 0}/600
                    </div>
                  );
                })()}
              </div>
              {form.formState.errors.productsServices && (
                <p className="text-sm text-red-600 mt-1">{form.formState.errors.productsServices.message}</p>
              )}
            </div>

            {/* Core Purpose */}
            <div>
              <Label htmlFor="corePurpose" className="text-sm font-medium text-gray-700">What's your brand's core purpose?</Label>
              <div className="relative group">
                <Textarea
                  id="corePurpose"
                  {...form.register('corePurpose')}
                  placeholder="To stop good local businesses from dying quietly, to 'Keep me visible even when I am too busy to show up, not just visibility, but validation. For those who want what the big brands have: presence, polish, and power, without the army it takes to get there.'"
                  className="mt-1 resize-none"
                  rows={3}
                  autoComplete="off"
                />
                <div className="absolute inset-x-0 top-full mt-1 bg-purple-50 border border-purple-200 rounded-lg p-3 opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-10">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-purple-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-purple-900 mb-1">your little helper:</p>
                      <p className="text-xs text-purple-800">Your core purpose defines your mission - focus on the customer jobs you help complete. Strong purposes connect emotionally to customer outcomes.</p>
                    </div>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between mt-2">
                <div className="flex items-center">
                  {(() => {
                    const corePurpose = form.watch('corePurpose') || '';
                    return corePurpose && corePurpose.length > 20 && (
                      <div className="flex items-center">
                        {corePurpose.length > 80 && (corePurpose.toLowerCase().includes('help') || corePurpose.toLowerCase().includes('stop') || corePurpose.toLowerCase().includes('enable') || corePurpose.toLowerCase().includes('empower')) ? (
                          <div className="flex items-center text-sm font-medium text-green-600 bg-green-50 px-2 py-1 rounded-md border border-green-200">
                            <div className="w-3 h-3 bg-green-600 rounded-full mr-2"></div>
                            Strong
                          </div>
                        ) : corePurpose.length > 40 ? (
                          <div className="flex items-center text-sm font-medium text-yellow-600 bg-yellow-50 px-2 py-1 rounded-md border border-yellow-200">
                            <div className="w-3 h-3 bg-yellow-600 rounded-full mr-2"></div>
                            Moderate
                          </div>
                        ) : (
                          <div className="flex items-center text-sm font-medium text-red-600 bg-red-50 px-2 py-1 rounded-md border border-red-200">
                            <div className="w-3 h-3 bg-red-600 rounded-full mr-2"></div>
                            Weak
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>
                {(() => {
                  const corePurpose = form.watch('corePurpose') || '';
                  return corePurpose && (
                    <div className={`text-xs ${corePurpose.length > 600 ? 'text-red-600 font-medium' : corePurpose.length > 540 ? 'text-yellow-600' : 'text-gray-500'}`}>
                      {corePurpose.length || 0}/600
                    </div>
                  );
                })()}
              </div>
              {form.formState.errors.corePurpose && (
                <p className="text-sm text-red-600 mt-1">{form.formState.errors.corePurpose.message}</p>
              )}
            </div>

            {/* AI Analysis Display */}
            {(showGuidance || isGeneratingGuidance) && (
              <Card className="bg-gradient-to-br from-indigo-50 via-purple-50 to-blue-50 border-indigo-200 shadow-lg">
                <CardContent className="p-6">
                  <div className="flex items-start space-x-4">
                    <div className="flex-shrink-0">
                      {isGeneratingGuidance ? (
                        <div className="w-12 h-12 bg-gradient-to-br from-purple-500 to-indigo-600 rounded-xl flex items-center justify-center shadow-lg">
                          <div className="w-6 h-6 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                        </div>
                      ) : (
                        <div className="w-12 h-12 bg-gradient-to-br from-purple-600 to-indigo-700 rounded-xl flex items-center justify-center shadow-lg">
                          <Bot className="w-6 h-6 text-white" />
                        </div>
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-2">
                          <h3 className="text-lg font-bold text-indigo-900 flex items-center">
                            <Lightbulb className="w-5 h-5 mr-2 text-amber-500" />
                            AI Analysis
                          </h3>
                          <div className="px-2 py-1 bg-indigo-100 text-indigo-700 text-xs font-medium rounded-full">
                            Value Proposition Canvas
                          </div>
                        </div>
                        {showGuidance && !isGeneratingGuidance && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setShowGuidance(false)}
                            className="h-8 w-8 p-0 text-gray-400 hover:text-gray-600 hover:bg-white/50 rounded-lg"
                          >
                            <X className="w-4 h-4" />
                          </Button>
                        )}
                      </div>
                      {isGeneratingGuidance ? (
                        <div className="space-y-3">
                          <p className="text-base text-indigo-800 font-medium">
                            Performing comprehensive Value Proposition Canvas analysis...
                          </p>
                          <div className="space-y-2 text-sm text-indigo-700">
                            <div className="flex items-center space-x-2">
                              <div className="w-2 h-2 bg-indigo-400 rounded-full animate-pulse"></div>
                              <span>Analyzing customer jobs (functional, emotional, social)</span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <div className="w-2 h-2 bg-indigo-400 rounded-full animate-pulse delay-150"></div>
                              <span>Mapping pain points and gain creators</span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <div className="w-2 h-2 bg-indigo-400 rounded-full animate-pulse delay-300"></div>
                              <span>Calculating Value Proposition-Market Fit score</span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <div className="w-2 h-2 bg-indigo-400 rounded-full animate-pulse delay-500"></div>
                              <span>Generating Queensland market insights</span>
                            </div>
                          </div>
                        </div>
                      ) : showGuidance && guidance ? (
                        <div className="bg-white/60 rounded-lg p-4 border border-indigo-100">
                          <div className="prose prose-sm max-w-none">
                            <div 
                              className="text-sm leading-relaxed text-gray-800 ai-content"
                              dangerouslySetInnerHTML={{
                                __html: guidance
                                  .replace(/## (.+)/g, '<h3 class="text-lg font-bold text-indigo-900 mt-4 mb-2 flex items-center"><span class="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>$1</h3>')
                                  .replace(/\*\*(.+?)\*\*/g, '<strong class="text-indigo-800 font-semibold">$1</strong>')
                                  .replace(/- (.+)/g, '<div class="flex items-start space-x-2 mb-1"><span class="w-1.5 h-1.5 bg-indigo-400 rounded-full mt-2 flex-shrink-0"></span><span>$1</span></div>')
                                  .replace(/(\d+)\. (.+)/g, '<div class="flex items-start space-x-2 mb-2"><span class="w-5 h-5 bg-indigo-500 text-white text-xs font-bold rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">$1</span><span class="font-medium">$2</span></div>')
                                  .replace(/\n\n/g, '<div class="mb-3"></div>')
                                  .replace(/\n/g, '<br>')
                              }}
                            />
                          </div>
                        </div>
                      ) : null}
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Ideal Audience */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <Label htmlFor="audience" className="text-sm font-medium text-gray-700">Who's your ideal audience?</Label>
                {aiSuggestions.audience && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => applySuggestion('audience', aiSuggestions.audience!)}
                    className="h-7 px-2 text-xs bg-indigo-50 border-indigo-200 text-indigo-700 hover:bg-indigo-100"
                  >
                    <Bot className="w-3 h-3 mr-1" />
                    Apply AI Suggestion
                  </Button>
                )}
              </div>
              <div className="relative group">
                <Textarea
                  id="audience"
                  {...form.register('audience')}
                  placeholder="Queensland SMEs, primarily businesses with 1-50 employees"
                  className="mt-1 resize-none"
                  rows={3}
                  autoComplete="off"
                />
                <div className="absolute inset-x-0 top-full mt-1 bg-purple-50 border border-purple-200 rounded-lg p-3 opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-10">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-purple-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-purple-900 mb-1">your little helper:</p>
                      <p className="text-xs text-purple-800">Define your customer segment - demographics, behaviors, and needs they share</p>
                    </div>
                  </div>
                </div>
              </div>
              {aiSuggestions.audience && (
                <div className="mt-2 p-3 bg-indigo-50 border border-indigo-200 rounded-lg">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-indigo-600 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <p className="text-xs font-medium text-indigo-900 mb-1">AI Recommendation:</p>
                      <p className="text-xs text-indigo-800">{aiSuggestions.audience}</p>
                    </div>
                  </div>
                </div>
              )}
              {(() => {
                const audience = form.watch('audience') || '';
                return audience && (
                  <div className="flex items-center justify-end mt-2">
                    <div className={`text-xs ${audience.length > 600 ? 'text-red-600 font-medium' : audience.length > 540 ? 'text-yellow-600' : 'text-gray-500'}`}>
                      {audience.length}/600
                    </div>
                  </div>
                );
              })()}
              {form.formState.errors.audience && (
                <p className="text-sm text-red-600 mt-1">{form.formState.errors.audience.message}</p>
              )}
            </div>

            {/* Job to Be Done */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <Label htmlFor="jobToBeDone" className="peer-disabled:cursor-not-allowed peer-disabled:opacity-70 text-sm text-gray-700 font-black">NB: What is the Job to be done (JTBD) for your customers?</Label>
                {aiSuggestions.jobToBeDone && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => applySuggestion('jobToBeDone', aiSuggestions.jobToBeDone!)}
                    className="h-7 px-2 text-xs bg-indigo-50 border-indigo-200 text-indigo-700 hover:bg-indigo-100"
                  >
                    <Bot className="w-3 h-3 mr-1" />
                    Apply AI Suggestion
                  </Button>
                )}
              </div>
              <div className="relative group">
                <Textarea
                  id="jobToBeDone"
                  {...form.register('jobToBeDone')}
                  placeholder="Streamline operations and automate business processes"
                  className="mt-1 resize-none"
                  rows={3}
                  autoComplete="off"
                />
                <div className="absolute inset-x-0 top-full mt-1 bg-purple-50 border border-purple-200 rounded-lg p-3 opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-10">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-purple-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-purple-900 mb-1">your little helper:</p>
                      <p className="text-xs text-purple-800">Customer job-to-be-done - what functional, emotional, or social job do customers hire you for?</p>
                    </div>
                  </div>
                </div>
              </div>
              {aiSuggestions.jobToBeDone && (
                <div className="mt-2 p-3 bg-indigo-50 border border-indigo-200 rounded-lg">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-indigo-600 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <p className="text-xs font-medium text-indigo-900 mb-1">JTBD Framework Analysis:</p>
                      <p className="text-xs text-indigo-800">{aiSuggestions.jobToBeDone}</p>
                    </div>
                  </div>
                </div>
              )}
              {(() => {
                const jobToBeDone = form.watch('jobToBeDone') || '';
                return jobToBeDone && (
                  <div className="flex items-center justify-end mt-2">
                    <div className={`text-xs ${jobToBeDone.length > 600 ? 'text-red-600 font-medium' : jobToBeDone.length > 540 ? 'text-yellow-600' : 'text-gray-500'}`}>
                      {jobToBeDone.length}/600
                    </div>
                  </div>
                );
              })()}
              {form.formState.errors.jobToBeDone && (
                <p className="text-sm text-red-600 mt-1">{form.formState.errors.jobToBeDone.message}</p>
              )}
            </div>

            {/* Motivations */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <Label htmlFor="motivations" className="text-sm font-medium text-gray-700">What motivates your audience?</Label>
                {aiSuggestions.motivations && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => applySuggestion('motivations', aiSuggestions.motivations!)}
                    className="h-7 px-2 text-xs bg-indigo-50 border-indigo-200 text-indigo-700 hover:bg-indigo-100"
                  >
                    <Bot className="w-3 h-3 mr-1" />
                    Apply AI Suggestion
                  </Button>
                )}
              </div>
              <div className="relative group">
                <Textarea
                  id="motivations"
                  {...form.register('motivations')}
                  placeholder="Feel confident and competitive in the digital landscape"
                  className="mt-1 resize-none"
                  rows={3}
                  autoComplete="off"
                />
                <div className="absolute inset-x-0 top-full mt-1 bg-purple-50 border border-purple-200 rounded-lg p-3 opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-10">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-purple-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-purple-900 mb-1">your little helper:</p>
                      <p className="text-xs text-purple-800">Customer gains - what benefits, outcomes, and characteristics your customers want</p>
                    </div>
                  </div>
                </div>
              </div>
              {aiSuggestions.motivations && (
                <div className="mt-2 p-3 bg-indigo-50 border border-indigo-200 rounded-lg">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-indigo-600 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <p className="text-xs font-medium text-indigo-900 mb-1">Customer Gains Analysis:</p>
                      <p className="text-xs text-indigo-800">{aiSuggestions.motivations}</p>
                    </div>
                  </div>
                </div>
              )}
              {(() => {
                const motivations = form.watch('motivations') || '';
                return motivations && (
                  <div className="flex items-center justify-end mt-2">
                    <div className={`text-xs ${motivations.length > 600 ? 'text-red-600 font-medium' : motivations.length > 540 ? 'text-yellow-600' : 'text-gray-500'}`}>
                      {motivations.length}/600
                    </div>
                  </div>
                );
              })()}
              {form.formState.errors.motivations && (
                <p className="text-sm text-red-600 mt-1">{form.formState.errors.motivations.message}</p>
              )}
            </div>

            {/* Pain Points */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <Label htmlFor="painPoints" className="text-sm font-medium text-gray-700">What are their pain points?</Label>
                {aiSuggestions.painPoints && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => applySuggestion('painPoints', aiSuggestions.painPoints!)}
                    className="h-7 px-2 text-xs bg-indigo-50 border-indigo-200 text-indigo-700 hover:bg-indigo-100"
                  >
                    <Bot className="w-3 h-3 mr-1" />
                    Apply AI Suggestion
                  </Button>
                )}
              </div>
              <div className="relative group">
                <Textarea
                  id="painPoints"
                  {...form.register('painPoints')}
                  placeholder="Fear of being left behind in the digital economy"
                  className="mt-1 resize-none"
                  rows={3}
                  autoComplete="off"
                />
                <div className="absolute inset-x-0 top-full mt-1 bg-purple-50 border border-purple-200 rounded-lg p-3 opacity-0 group-hover:opacity-100 transition-opacity duration-200 z-10">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-purple-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-purple-900 mb-1">your little helper:</p>
                      <p className="text-xs text-purple-800">Customer pains - frustrations, obstacles, and risks your customers experience</p>
                    </div>
                  </div>
                </div>
              </div>
              {aiSuggestions.painPoints && (
                <div className="mt-2 p-3 bg-indigo-50 border border-indigo-200 rounded-lg">
                  <div className="flex items-start space-x-2">
                    <Bot className="w-4 h-4 text-indigo-600 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <p className="text-xs font-medium text-indigo-900 mb-1">Customer Pains Analysis:</p>
                      <p className="text-xs text-indigo-800">{aiSuggestions.painPoints}</p>
                    </div>
                  </div>
                </div>
              )}
              {(() => {
                const painPoints = form.watch('painPoints') || '';
                return painPoints && (
                  <div className="flex items-center justify-end mt-2">
                    <div className={`text-xs ${painPoints.length > 600 ? 'text-red-600 font-medium' : painPoints.length > 540 ? 'text-yellow-600' : 'text-gray-500'}`}>
                      {painPoints.length}/600
                    </div>
                  </div>
                );
              })()}
              {form.formState.errors.painPoints && (
                <p className="text-sm text-red-600 mt-1">{form.formState.errors.painPoints.message}</p>
              )}
            </div>

            {/* Goals with Measurable Metrics */}
            <div>
              <Label className="text-sm font-medium text-gray-700">What are your specific goals with measurable targets?</Label>
              <div className="text-xs text-purple-600 mt-1 mb-3 flex items-center">
                <div className="w-4 h-4 rounded-full mr-1" style={{ backgroundColor: '#915fd7' }}></div>
                your little helper: Your value proposition must align with customer jobs, pains, and gains. Select measurable goals.
              </div>
              <div className="mt-3 space-y-4">
                <div className="flex items-start space-x-3">
                  <Checkbox
                    id="driveTraffic"
                    checked={form.watch('goals.driveTraffic')}
                    onCheckedChange={(checked) => form.setValue('goals.driveTraffic', !!checked)}
                  />
                  <div className="flex-1">
                    <Label htmlFor="driveTraffic" className="text-sm text-gray-700">Drive traffic to website</Label>
                    {form.watch('goals.driveTraffic') && (
                      <div className="mt-2 space-y-2">
                        <Input
                          id="websiteUrl"
                          {...form.register('goals.websiteUrl')}
                          placeholder="Enter website URL (e.g., https://queenslandartisans.com)"
                          autoComplete="url"
                        />
                        <Input
                          id="trafficTarget"
                          {...form.register('goals.trafficTarget')}
                          placeholder="Monthly traffic target (e.g., 500 visitors per month)"
                          autoComplete="off"
                        />
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <Checkbox
                    id="buildBrand"
                    checked={form.watch('goals.buildBrand')}
                    onCheckedChange={(checked) => form.setValue('goals.buildBrand', !!checked)}
                  />
                  <div className="flex-1">
                    <Label htmlFor="buildBrand" className="text-sm text-gray-700">Build brand awareness</Label>
                    {form.watch('goals.buildBrand') && (
                      <div className="mt-2 space-y-2">
                        <Input
                          id="followerTarget"
                          {...form.register('goals.followerTarget')}
                          placeholder="Follower growth target (e.g., 200 new followers per month)"
                          autoComplete="off"
                        />
                        <Input
                          id="reachTarget"
                          {...form.register('goals.reachTarget')}
                          placeholder="Monthly reach target (e.g., 5,000 people reached)"
                          autoComplete="off"
                        />
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <Checkbox
                    id="makeSales"
                    checked={form.watch('goals.makeSales')}
                    onCheckedChange={(checked) => form.setValue('goals.makeSales', !!checked)}
                  />
                  <div className="flex-1">
                    <Label htmlFor="makeSales" className="text-sm text-gray-700">Generate sales</Label>
                    {form.watch('goals.makeSales') && (
                      <div className="mt-2 space-y-2">
                        <Input
                          id="salesUrl"
                          {...form.register('goals.salesUrl')}
                          placeholder="Enter sales URL (e.g., https://queenslandartisans.com/shop)"
                          autoComplete="url"
                        />
                        <Input
                          id="salesTarget"
                          {...form.register('goals.salesTarget')}
                          placeholder="Monthly sales target (e.g., $2,000 revenue per month)"
                          autoComplete="off"
                        />
                        <Input
                          id="conversionTarget"
                          {...form.register('goals.conversionTarget')}
                          placeholder="Conversion rate target (e.g., 3% of visitors make purchase)"
                          autoComplete="off"
                        />
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <Checkbox
                    id="generateLeads"
                    checked={form.watch('goals.generateLeads')}
                    onCheckedChange={(checked) => form.setValue('goals.generateLeads', !!checked)}
                  />
                  <div className="flex-1">
                    <Label htmlFor="generateLeads" className="text-sm text-gray-700">Generate leads</Label>
                    {form.watch('goals.generateLeads') && (
                      <div className="mt-2 space-y-2">
                        <Input
                          id="leadTarget"
                          {...form.register('goals.leadTarget')}
                          placeholder="Monthly lead target (e.g., 50 qualified leads per month)"
                          autoComplete="off"
                        />
                        <Input
                          id="engagementTarget"
                          {...form.register('goals.engagementTarget')}
                          placeholder="Engagement rate target (e.g., 4% average engagement rate)"
                          autoComplete="off"
                        />
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-start space-x-3">
                  <Checkbox
                    id="informEducate"
                    checked={form.watch('goals.informEducate')}
                    onCheckedChange={(checked) => form.setValue('goals.informEducate', !!checked)}
                  />
                  <div className="flex-1">
                    <Label htmlFor="informEducate" className="text-sm text-gray-700">Inform or educate</Label>
                    {form.watch('goals.informEducate') && (
                      <div className="mt-2 space-y-2">
                        <Textarea
                          id="keyMessage"
                          {...form.register('goals.keyMessage')}
                          placeholder="What's your key message? (e.g., promote sustainability in art)"
                          className="resize-none"
                          rows={2}
                          autoComplete="off"
                        />
                        <Input
                          id="educationTarget"
                          {...form.register('goals.educationTarget')}
                          placeholder="Education goal (e.g., 1,000 people educated about sustainability monthly)"
                          autoComplete="off"
                        />
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Logo Upload */}
            <div>
              <Label htmlFor="logo" className="text-sm font-medium text-gray-700">Upload your brand logo</Label>
              <div className="mt-2 flex items-start space-x-4">
                <div className="flex-1">
                  <Input
                    id="logo"
                    type="file"
                    accept="image/png,image/jpeg,image/jpg"
                    onChange={handleLogoUpload}
                    className="hidden"
                  />
                  <Label
                    htmlFor="logo"
                    className="cursor-pointer inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-700 hover:bg-gray-50"
                  >
                    <Upload className="h-4 w-4 mr-2" />
                    Choose File
                  </Label>
                  {logoFile && (
                    <span className="text-sm text-gray-600 ml-3">{logoFile.name}</span>
                  )}
                  <p className="text-xs text-gray-500 mt-1">Max 500KB, 100x100px minimum, 1000x1000px maximum, PNG/JPG only</p>
                </div>
                {logoPreview && (
                  <div className="flex-shrink-0">
                    <div className="relative w-20 h-20 border border-gray-300 rounded-lg overflow-hidden bg-gray-50 flex items-center justify-center">
                      <img 
                        src={logoPreview} 
                        alt="Logo preview" 
                        className="max-w-full max-h-full object-contain"
                      />
                      <button
                        type="button"
                        onClick={handleDeleteLogo}
                        className="absolute -top-2 -right-2 w-6 h-6 bg-red-500 hover:bg-red-600 text-white rounded-full flex items-center justify-center text-xs transition-colors"
                        title="Delete logo"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </div>
                    <p className="text-xs text-green-600 text-center mt-1">Preview</p>
                    <div className="flex justify-center mt-1">
                      <Label
                        htmlFor="logo"
                        className="cursor-pointer text-xs text-blue-600 hover:text-blue-800"
                      >
                        Change Logo
                      </Label>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Contact Details */}
            <div>
              <Label className="text-sm font-medium text-gray-700">Contact Details</Label>
              <div className="mt-3 space-y-4 contact-details">
                <div>
                  <Label htmlFor="email" className="text-sm text-gray-600">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    {...form.register('contactDetails.email')}
                    placeholder="info@queenslandartisans.com"
                    className="mt-1"
                    autoComplete="off"
                  />
                  {form.formState.errors.contactDetails?.email && (
                    <p className="text-sm text-red-600 mt-1">{form.formState.errors.contactDetails.email.message}</p>
                  )}
                </div>
                <div>
                  <Label htmlFor="phone" className="text-sm text-gray-600">Phone</Label>
                  <Input
                    id="phone"
                    type="tel"
                    {...form.register('contactDetails.phone')}
                    placeholder="+61 7 1234 5678"
                    className="mt-1"
                    autoComplete="tel"
                  />
                </div>
              </div>
            </div>

            <Button 
              type="submit" 
              className="w-full bg-blue-600 hover:bg-blue-700 text-white py-4 text-lg font-medium mt-6"
              disabled={loading}
              style={{ backgroundColor: '#3250fa' }}
            >
              {loading ? "Saving Brand Purpose..." : "Save Brand Purpose & Continue"}
            </Button>
          </form>
            </div>
          </div>
          
          {/* Training Wizard Sidebar */}
          <div className="lg:col-span-1">
            <OnboardingWizard />
          </div>
        </div>
      </div>
      
      <MasterFooter />
    </div>
  );
}

// Enhanced Grok autofill with visible feedback and AI methodology
// GROK AUTOFILL FUNCTION REMOVED TO PREVENT INFINITE API LOOPS

