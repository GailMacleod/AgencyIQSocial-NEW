import React, { useId } from 'react';
import { LucideIcon } from 'lucide-react';

interface AnimatedIconProps {
  icon: LucideIcon;
  colorScheme: 'blue' | 'cyan' | 'pink' | 'purple' | 'gradient';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const AnimatedIcon: React.FC<AnimatedIconProps> = ({ 
  icon: Icon, 
  colorScheme, 
  size = 'md',
  className = '' 
}) => {
  const gradientId = useId();
  const glowId = useId();
  
  const sizeClasses = {
    sm: 'w-10 h-10',
    md: 'w-12 h-12',
    lg: 'w-16 h-16'
  };

  const iconSizes = {
    sm: 'w-4 h-4',
    md: 'w-5 h-5',
    lg: 'w-6 h-6'
  };

  const strokeWidths = {
    sm: '1.5',
    md: '2',
    lg: '2.5'
  };

  const getGradientColors = () => {
    switch (colorScheme) {
      case 'blue':
        return {
          colors: ['#3250fa', '#4a6bff', '#5c7cff', '#3250fa'],
          shadow: 'rgba(50, 80, 250, 0.6)'
        };
      case 'cyan':
        return {
          colors: ['#00f0ff', '#33f3ff', '#66f6ff', '#00f0ff'],
          shadow: 'rgba(0, 240, 255, 0.6)'
        };
      case 'pink':
        return {
          colors: ['#ff538f', '#ff75a8', '#ff97c1', '#ff538f'],
          shadow: 'rgba(255, 83, 143, 0.6)'
        };
      case 'purple':
        return {
          colors: ['#3250fa', '#8b66ff', '#d477ff', '#ff538f'],
          shadow: 'rgba(139, 102, 255, 0.6)'
        };
      case 'gradient':
        return {
          colors: ['#3250fa', '#00f0ff', '#ff538f', '#3250fa'],
          shadow: 'rgba(50, 80, 250, 0.6)'
        };
      default:
        return {
          colors: ['#3250fa', '#00f0ff', '#3250fa', '#00f0ff'],
          shadow: 'rgba(50, 80, 250, 0.6)'
        };
    }
  };

  const { colors, shadow } = getGradientColors();

  return (
    <div className={`relative ${className}`}>
      <div 
        className={`
          ${sizeClasses[size]}
          flex items-center justify-center
          transition-all duration-500 ease-in-out
          hover:scale-110
        `}
      >
        {/* SVG with gradient definitions */}
        <svg 
          width="0" 
          height="0" 
          style={{ position: 'absolute' }}
        >
          <defs>
            {/* Animated gradient for stroke */}
            <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={colors[0]} stopOpacity="1">
                <animate 
                  attributeName="stop-color" 
                  values={colors.join(';')}
                  dur="3s" 
                  repeatCount="indefinite" 
                />
              </stop>
              <stop offset="33%" stopColor={colors[1]} stopOpacity="0.9">
                <animate 
                  attributeName="stop-color" 
                  values={colors.slice(1).concat(colors[0]).join(';')}
                  dur="3s" 
                  repeatCount="indefinite" 
                />
              </stop>
              <stop offset="66%" stopColor={colors[2]} stopOpacity="0.8">
                <animate 
                  attributeName="stop-color" 
                  values={colors.slice(2).concat(colors.slice(0, 2)).join(';')}
                  dur="3s" 
                  repeatCount="indefinite" 
                />
              </stop>
              <stop offset="100%" stopColor={colors[3]} stopOpacity="1">
                <animate 
                  attributeName="stop-color" 
                  values={colors.slice(3).concat(colors.slice(0, 3)).join(';')}
                  dur="3s" 
                  repeatCount="indefinite" 
                />
              </stop>
            </linearGradient>
            
            {/* Glow effect filter */}
            <filter id={glowId} x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
              <feMerge> 
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>
        </svg>
        
        {/* Render the icon with gradient stroke and glow */}
        <Icon 
          className={`${iconSizes[size]} transition-all duration-300`}
          strokeWidth={strokeWidths[size]}
          fill="none"
          style={{
            stroke: `url(#${gradientId})`,
            filter: `url(#${glowId}) drop-shadow(0 0 8px ${shadow})`,
            strokeLinecap: 'round',
            strokeLinejoin: 'round'
          }}
        />
      </div>
    </div>
  );
};

// CSS for slow spin animation - add this to your global styles
const styles = `
  @keyframes spin-slow {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
  
  .animate-spin-slow {
    animation: spin-slow 8s linear infinite;
  }
`;

// Export styles to be added to global CSS
export { styles as animatedIconStyles };