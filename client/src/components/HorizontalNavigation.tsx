import { useLocation } from "wouter";
import { Target, Users, Calendar, Send, BarChart3, Settings } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { cn } from "@/lib/utils";

interface NavItem {
  id: string;
  label: string;
  icon: React.ElementType;
  route: string;
  description: string;
  requiresSubscription: boolean;
  requiresBrandPurpose?: boolean;
  requiresPlatformConnection?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  {
    id: "brand-purpose",
    label: "Brand Purpose",
    icon: Target,
    route: "/brand-purpose",
    description: "Define your brand",
    requiresSubscription: false, // Brand purpose is accessible for onboarding
  },
  {
    id: "schedule",
    label: "Social Schedule",
    icon: Calendar,
    route: "/schedule",
    description: "Auto Schedule Posts",
    requiresSubscription: true,
    requiresBrandPurpose: true,
  },
  {
    id: "platform-connect",
    label: "Platform Connect",
    icon: Users,
    route: "/platform-connections",
    description: "Connect Accounts",
    requiresSubscription: true,
  },

  {
    id: "analytics",
    label: "Analytics",
    icon: BarChart3,
    route: "/analytics",
    description: "Track Performance",
    requiresSubscription: true,
  }
];

export default function HorizontalNavigation() {
  const [location, setLocation] = useLocation();
  
  // Fetch user data to check subscription status
  const { data: user } = useQuery({
    queryKey: ["/api/user"],
    staleTime: 5 * 60 * 1000,
  });

  // Fetch brand purpose to check completion
  const { data: brandPurpose } = useQuery({
    queryKey: ["/api/brand-purpose"],
    enabled: !!user,
  });

  // Fetch platform connections to check status
  const { data: platformConnections } = useQuery({
    queryKey: ["/api/platform-connections"],
    enabled: !!user,
  });

  // Check if user has active subscription
  const hasActiveSubscription = (user as any)?.subscriptionPlan && 
    (user as any).subscriptionPlan !== '' && 
    (user as any).subscriptionPlan !== 'none';

  // Check if brand purpose is completed
  const brandPurposeCompleted = brandPurpose && (brandPurpose as any).businessName;

  // Check if platforms are connected
  const platformsConnected = platformConnections && Array.isArray(platformConnections) && platformConnections.length > 0;

  // Determine which step user should focus on next
  const getNextStep = (): string => {
    if (!hasActiveSubscription) return "subscription";
    if (!brandPurposeCompleted) return "brand-purpose";
    if (!platformsConnected) return "platform-connect";
    return "schedule";
  };

  const nextStep = getNextStep();

  // Handle navigation clicks with subscription wall enforcement
  const handleNavClick = (item: NavItem) => {
    // Always allow brand purpose access for onboarding
    if (item.id === "brand-purpose") {
      setLocation(item.route);
      return;
    }

    // Enforce subscription wall for all other features
    if (item.requiresSubscription && !hasActiveSubscription) {
      setLocation("/subscription");
      return;
    }

    // For subscribers, allow access to all steps directly
    // The individual pages will handle any missing prerequisites with helpful messaging
    setLocation(item.route);
  };

  // Determine icon state and styling
  const getIconState = (item: NavItem) => {
    // If this is the next step, make it throb
    if (item.id === nextStep) {
      return "next";
    }

    // Only disable if subscription is required and not active
    if (item.requiresSubscription && !hasActiveSubscription) {
      return "disabled";
    }

    // For subscribers, show all steps as available (they can access them all)
    // The navigation logic will redirect them to prerequisites if needed
    return "available";
  };

  return (
    <section className="py-8 sm:py-16 bg-white">
      <div className="container-atomiq">
        <div className="text-center space-y-2 sm:space-y-4 mb-8 sm:mb-12 px-4 sm:px-0">
          <h3 className="text-2xl sm:text-4xl md:text-5xl font-bold text-[#3b5cff]">
            Your Workflow
          </h3>
          <p className="text-base sm:text-xl max-w-3xl mx-auto text-[#3253eb] font-semibold">
            Social Media automation in 4 simple steps
          </p>
        </div>

        {/* Horizontal Navigation Bar */}
        <div className="flex flex-wrap justify-center items-center gap-4 md:gap-8 max-w-4xl mx-auto">
          {NAV_ITEMS.map((item, index) => {
            const IconComponent = item.icon;
            const iconState = getIconState(item);
            
            return (
              <div key={item.id} className="flex items-center">
                {/* Navigation Item - Compact Design */}
                <button
                  onClick={() => handleNavClick(item)}
                  className={cn(
                    "group flex flex-col items-center p-3 transition-all duration-300 hover:scale-105",
                    "text-center min-w-[80px]",
                    iconState === "next" && "animate-slow-pulse",
                    iconState === "disabled" && "opacity-60 cursor-not-allowed"
                  )}
                  disabled={iconState === "disabled"}
                >
                  {/* Icon */}
                  <div className="flex justify-center mb-2">
                    <IconComponent className={cn(
                      "w-6 h-6 transition-colors",
                      iconState === "next" && "text-[#00f0ff]",
                      iconState === "available" && "text-[#3250fa]",
                      iconState === "available" && "text-[#3250fa]",
                      iconState === "disabled" && "text-gray-400"
                    )} />
                  </div>
                  
                  {/* Label Only */}
                  <span className={cn(
                    "text-xs font-medium",
                    iconState === "next" && "text-[#00f0ff]",
                    iconState === "available" && "text-[#3250fa]",
                    iconState === "available" && "text-[#3250fa]",
                    iconState === "disabled" && "text-gray-400"
                  )}>
                    {item.label}
                  </span>
                </button>

                {/* Arrow between items (except last) */}
                {index < NAV_ITEMS.length - 1 && (
                  <div className="hidden md:block mx-2">
                    <svg 
                      className="w-4 h-4 text-[#3250fa]" 
                      fill="none" 
                      stroke="currentColor" 
                      viewBox="0 0 24 24"
                    >
                      <path 
                        strokeLinecap="round" 
                        strokeLinejoin="round" 
                        strokeWidth={2} 
                        d="M9 5l7 7-7 7" 
                      />
                    </svg>
                  </div>
                )}
              </div>
            );
          })}
        </div>


      </div>
    </section>
  );
}