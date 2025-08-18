import { TooltipProvider } from "@/components/ui/tooltip";
import { memo, useMemo } from "react";

interface OptimizedTooltipProviderProps {
  children: React.ReactNode;
}

// Memoized TooltipProvider to prevent unnecessary re-renders in large apps
const OptimizedTooltipProvider = memo(({ children }: OptimizedTooltipProviderProps) => {
  // Use useMemo to prevent recreation of tooltip context value
  const tooltipContextValue = useMemo(() => ({}), []);
  
  return (
    <TooltipProvider 
      delayDuration={300} // Optimize tooltip delay for performance
      skipDelayDuration={100} // Reduce skip delay for better UX
    >
      {children}
    </TooltipProvider>
  );
});

OptimizedTooltipProvider.displayName = "OptimizedTooltipProvider";

export default OptimizedTooltipProvider;