# TheAgencyIQ - Complete Navigation Architecture

## Overview
TheAgencyIQ implements a sophisticated dual-path navigation system with distinct user flows for subscribers and potential customers, managed through dynamic user type detection and comprehensive wizard guidance.

## User Type Detection System

### `/api/user-status` Endpoint
- **Purpose**: Determines user type and subscription status
- **Returns**: `{ userType: 'new' | 'returning', hasActiveSubscription: boolean, hasBrandSetup: boolean, hasConnections: boolean }`
- **Integration**: OnboardingWizard.tsx checks this endpoint to set `isDemoMode`

### User Classification
1. **Non-Subscribers** (Demo Mode): `!hasActiveSubscription`
2. **Subscribers** (Functional Mode): `hasActiveSubscription === true`

---

## NAVIGATION PATHS

### 1. NON-SUBSCRIBERS (Demo Mode Path)

#### Entry Point: Landing Page
- **Route**: `/` (splash.tsx)
- **Key Elements**:
  - "Set & forget social media for QLD small business" heading
  - Education icon (64x64px) above "Technology Intelligence - BETA" button
  - "Subscribe Now" button (#3250fa with #00f0ff pulse animation)
  - Subscription pricing cards (Starter $19.99, Growth $41.99, Professional $99.99)

#### Demo Wizard Flow (OnboardingWizard.tsx - Demo Mode)
**Wizard Stage 1: Welcome**
- **Content**: Platform overview and value proposition
- **Navigation**: "Next" button only
- **Badge**: "Demo Mode" displayed

**Wizard Stage 2: AI Content Generation Preview**
- **Content**: Demonstrates AI-powered content creation (preview only)
- **Navigation**: "Next" button only
- **Features**: Shows content generation capabilities without functionality

**Wizard Stage 3: Brand Purpose Preview**
- **Content**: Explains brand purpose setup process
- **Navigation**: "Next" button only
- **Features**: Preview of brand alignment system

**Wizard Stage 4: Platform Connections Preview**
- **Content**: Shows 5-platform integration (Facebook, Instagram, LinkedIn, YouTube, X)
- **Navigation**: "Next" button only
- **Features**: OAuth connection previews without actual connection

**Wizard Stage 5: Analytics Dashboard Preview**
- **Content**: Demonstrates analytics and performance tracking
- **Navigation**: "Next" button only
- **Features**: Sample analytics data display

**Wizard Stage 6: Subscribe Now CTA**
- **Content**: Compelling subscription call-to-action with feature highlights
- **Navigation**: "Subscribe Now" button → `/subscription`
- **Features**: Final conversion step with subscription benefits

#### Demo Mode Restrictions
- All functional buttons disabled or redirect to subscription page
- No quota consumption allowed
- No actual platform connections
- No content generation capabilities
- All data displays are preview/demonstration only

---

### 2. SUBSCRIBERS (Functional Path)

#### Entry Point: Authentication
- **Route**: `/login` → Redirects to `/schedule` (intelligent-schedule.tsx)
- **Authentication**: Phone number + password verification
- **Session**: Establishes `req.session.userId` and subscription validation

#### Subscriber Wizard Flow (OnboardingWizard.tsx - Functional Mode)
**Wizard Stage 1: Welcome (Returning Subscriber)**
- **Content**: Welcome back message with current subscription status
- **Navigation**: "Next" button advances to current workflow step
- **Badge**: "Returning Subscriber" displayed

**Wizard Stage 2: AI Content Generation**
- **Route**: `/intelligent-schedule` (intelligent-schedule.tsx)
- **Content**: Functional AI content generation interface
- **Features**: 
  - Real Grok AI integration
  - Quota consumption (52 posts for Professional plan)
  - Platform-specific content optimization
  - Video generation capabilities
- **Navigation**: Generate content → Brand Purpose setup

**Wizard Stage 3: Brand Purpose Setup**
- **Route**: `/brand-purpose` (brand-purpose.tsx)
- **Content**: Define brand purpose for content alignment
- **Features**:
  - Brand name, core purpose, target audience
  - Jobs-to-be-done framework integration
  - Content strategy alignment
- **Navigation**: Save brand purpose → Platform connections

**Wizard Stage 4: Platform Connections**
- **Route**: `/connect-platforms` (connect-platforms.tsx)
- **Content**: OAuth connection management for 5 platforms
- **Features**:
  - Live OAuth flows (Facebook, Instagram, LinkedIn, YouTube, X)
  - Token refresh management
  - Connection status monitoring
- **Navigation**: Connect platforms → Analytics monitoring

**Wizard Stage 5: Analytics Dashboard**
- **Route**: `/analytics` (analytics.tsx)
- **Content**: Real-time performance analytics
- **Features**:
  - Platform-specific metrics
  - Engagement tracking
  - Performance optimization insights
- **Navigation**: Review analytics → Ongoing workflow

**Wizard Stage 6: Workflow Complete**
- **Content**: Confirmation of setup completion
- **Navigation**: Return to main dashboard workflow

---

## MAIN APPLICATION ROUTES

### Core Functional Pages (Subscribers Only)
1. **`/intelligent-schedule`** - AI Content Generation Hub
2. **`/brand-purpose`** - Brand Strategy Setup
3. **`/connect-platforms`** - Platform OAuth Management
4. **`/analytics`** - Performance Analytics Dashboard
5. **`/subscription`** - Subscription Management
6. **`/profile`** - User Profile Settings

### Support & Utility Pages
1. **`/login`** - Authentication Interface
2. **`/reset-password`** - Password Recovery
3. **`/redeem-certificate`** - Gift Certificate Redemption
4. **`/logout`** - Session Termination
5. **`/admin`** - Administrative Dashboard (Role-based)

### Platform Integration Pages
1. **`/token-status`** - OAuth Token Management
2. **`/connection-repair`** - Platform Connection Repair
3. **`/oauth-reconnect`** - OAuth Reconnection Interface
4. **`/oauth-diagnostic`** - OAuth Diagnostic Tools
5. **`/instagram-fix`** - Instagram-specific Connection Repair

### Additional Features
1. **`/video-gen`** - Video Generation Interface
2. **`/yearly-analytics`** - Extended Analytics View
3. **`/grok-test`** - AI Integration Testing
4. **`/data-deletion-status`** - GDPR Compliance Interface

---

## AUTHENTICATION & ACCESS CONTROL

### Middleware Implementation
- **`requireActiveSubscription`**: Blocks access to functional features for non-subscribers
- **`requireAuth`**: Basic authentication checking for logged-in users
- **Session Management**: Express-session with PostgreSQL storage

### Access Control Matrix
| Route | Non-Subscriber | Subscriber |
|-------|----------------|------------|
| `/` | ✅ Full Access | ✅ Full Access |
| `/subscription` | ✅ Full Access | ✅ Full Access |
| `/login` | ✅ Full Access | ✅ Full Access |
| `/intelligent-schedule` | ❌ Redirect to `/subscription` | ✅ Full Access |
| `/brand-purpose` | ❌ Redirect to `/subscription` | ✅ Full Access |
| `/connect-platforms` | ❌ Redirect to `/subscription` | ✅ Full Access |
| `/analytics` | ❌ Redirect to `/subscription` | ✅ Full Access |
| `/profile` | ❌ Redirect to `/subscription` | ✅ Full Access |

---

## WIZARD ARCHITECTURAL INTEGRATION

### URL-Based Step Detection
```typescript
const getSubscriberStepFromUrl = (url: string) => {
  switch (url) {
    case '/intelligent-schedule': return 1; // AI Content Generation
    case '/brand-purpose': return 2; // Brand Purpose Setup
    case '/connect-platforms': return 3; // Platform Connections
    case '/analytics': return 4; // Analytics Dashboard
    default: return 0; // Welcome
  }
};
```

### Progress Persistence
- **Storage**: `localStorage` with 24-hour expiration
- **Data**: `{ currentStep, completedSteps, skippedSteps, isSkipped, timestamp }`
- **Scope**: Per-session progress tracking with resume capability

### Dynamic Mode Switching
- **Detection**: Real-time subscription status checking
- **Implementation**: `setIsDemoMode(!hasActiveSubscription)`
- **UI Changes**: Wizard content, navigation options, feature access

---

## MOBILE NAVIGATION MENU

### Core Navigation Items
1. **Dashboard** → `/` (Home)
2. **Generate Content** → `/intelligent-schedule` (with quota badge)
3. **Manage Posts** → `/schedule`
4. **Analytics** → `/yearly-analytics`
5. **Platform Setup** → `/token-status`
6. **Subscription** → `/subscription`
7. **Profile** → `/profile`

### Quota Integration
- **Display**: Remaining posts count (`${quotaData.remainingPosts} left`)
- **Limits**: "Limit reached" when quota exhausted
- **Color Coding**: Visual indicators for quota status

---

## SUBSCRIPTION FLOW ARCHITECTURE

### New User Journey
1. **Landing Page** (`/`) → **Subscription Selection** (`/subscription`)
2. **Payment Processing** → **Account Creation**
3. **Login Redirect** → **AI Content Generation** (`/intelligent-schedule`)
4. **Wizard Guidance** → **Brand Purpose** → **Platform Connections** → **Analytics**

### Returning User Journey
1. **Direct Login** (`/login`) → **AI Content Generation** (`/intelligent-schedule`)
2. **Wizard Resume** → **Continue from last step or current page context**
3. **Full Feature Access** → **All functional routes available**

---

## TECHNICAL IMPLEMENTATION NOTES

### Key Components
- **OnboardingWizard.tsx**: Central wizard management with dual-mode support
- **subscriptionAuth.ts**: Middleware for access control
- **user-status API**: Dynamic user type detection
- **Session Management**: PostgreSQL-backed session storage

### State Management
- **React Query**: API state management and caching
- **LocalStorage**: Wizard progress persistence
- **Session Storage**: User authentication state

### Security Implementation
- **CORS**: Platform-specific headers for OAuth flows
- **CSP**: Content Security Policy for external integrations
- **Token Refresh**: Automatic OAuth token management

---

## CONCLUSION

TheAgencyIQ's navigation architecture successfully implements a sophisticated dual-path system that:
1. **Guides non-subscribers** through compelling demo experiences ending in subscription conversion
2. **Provides subscribers** with full functional access through guided wizard workflows
3. **Maintains security** through proper authentication and access control
4. **Ensures scalability** through modular component architecture and dynamic user type detection

This architecture supports both user acquisition (demo mode) and customer success (functional mode) while maintaining clean separation of concerns and professional user experience standards.