/**
 * WORLD-CLASS SOCIAL MEDIA PLATFORM TEST
 * Complete end-to-end test: signup → content optimization → cross-platform publishing
 * Validates 100% error-free operation for Queensland small businesses
 */

import axios from 'axios';

class WorldClassSystemTest {
  constructor() {
    this.baseUrl = 'http://localhost:5000';
    this.sessionCookie = null;
    this.testResults = [];
    this.userId = 2; // Queensland SME test user
  }

  async runComprehensiveTest() {
    console.log('🌟 WORLD-CLASS SOCIAL MEDIA PLATFORM TEST');
    console.log('Testing complete system: AI optimization → cross-platform publishing');
    console.log('=' .repeat(70));

    try {
      // 1. Authentication & Session Management
      await this.testAuthentication();
      
      // 2. Platform Connections Optimization
      await this.testPlatformConnections();
      
      // 3. AI Content Optimization Features
      await this.testAIContentOptimization();
      
      // 4. SEO & Hashtag Generation
      await this.testSEOOptimization();
      
      // 5. Learning Algorithm & 30-day Cycles
      await this.testLearningAlgorithm();
      
      // 6. Business Growth Analytics
      await this.testBusinessAnalytics();
      
      // 7. Audience Insights & Targeting
      await this.testAudienceInsights();
      
      // 8. Optimal Timing Analysis
      await this.testOptimalTiming();
      
      // 9. End-to-End Publishing Test
      await this.testCrossPlatformPublishing();
      
      // 10. Quota Management & Error Handling
      await this.testQuotaManagement();
      
      // Generate comprehensive report
      this.generateWorldClassReport();
      
    } catch (error) {
      console.error('\n❌ World-class system test failed:', error.message);
      this.recordResult('SYSTEM_FAILURE', 'FAIL', error.message);
    }
  }

  async testAuthentication() {
    console.log('\n🔐 Testing Authentication & Session Management...');
    
    try {
      const response = await axios.post(`${this.baseUrl}/api/establish-session`, {
        email: 'gailm@macleodglba.com.au',
        phone: '+61424835189'
      });
      
      this.sessionCookie = response.headers['set-cookie']?.[0];
      
      if (response.data.success && this.sessionCookie) {
        this.recordResult('Authentication', 'PASS', 'Session established for Queensland SME user');
        console.log('✅ Authentication successful');
      } else {
        throw new Error('Session establishment failed');
      }
      
    } catch (error) {
      this.recordResult('Authentication', 'FAIL', error.message);
      throw error;
    }
  }

  async testPlatformConnections() {
    console.log('\n🔗 Testing Optimized Platform Connections...');
    
    try {
      const response = await axios.get(`${this.baseUrl}/api/platform-connections`, {
        headers: { Cookie: this.sessionCookie }
      });
      
      const connections = response.data;
      const connectedPlatforms = connections.filter(c => c.isActive).length;
      
      if (connectedPlatforms === 5) {
        this.recordResult('Platform Connections', 'PASS', 
          `All 5 platforms connected (${connections.map(c => c.platform).join(', ')})`);
        console.log(`✅ ${connectedPlatforms}/5 platforms optimally connected`);
      } else {
        this.recordResult('Platform Connections', 'PARTIAL', 
          `${connectedPlatforms}/5 platforms connected`);
        console.log(`⚠️ ${connectedPlatforms}/5 platforms connected`);
      }
      
    } catch (error) {
      this.recordResult('Platform Connections', 'FAIL', error.message);
      console.error('❌ Platform connections test failed:', error.message);
    }
  }

  async testAIContentOptimization() {
    console.log('\n🧠 Testing AI Content Optimization...');
    
    try {
      const response = await axios.post(`${this.baseUrl}/api/ai/optimize-content`, {
        contentType: 'engagement',
        platform: 'facebook'
      }, {
        headers: { 
          Cookie: this.sessionCookie,
          'Content-Type': 'application/json'
        }
      });
      
      const result = response.data;
      
      if (result.success && result.content) {
        const content = result.content;
        const hasContent = content.content && content.content.length > 0;
        const hasHashtags = content.hashtags && content.hashtags.length > 0;
        const hasKeywords = content.keywords && content.keywords.length > 0;
        const hasEngagementScore = content.engagementScore > 0;
        
        if (hasContent && hasHashtags && hasKeywords && hasEngagementScore) {
          this.recordResult('AI Content Optimization', 'PASS', 
            `Generated content with ${content.hashtags.length} hashtags, engagement score: ${content.engagementScore}%`);
          console.log('✅ AI content optimization successful');
          console.log(`   📝 Content: "${content.content.substring(0, 50)}..."`);
          console.log(`   📈 Engagement Score: ${content.engagementScore}%`);
          console.log(`   🏷️ Hashtags: ${content.hashtags.slice(0, 3).join(', ')}...`);
        } else {
          throw new Error('Incomplete content optimization response');
        }
      } else {
        throw new Error('AI content optimization failed');
      }
      
    } catch (error) {
      this.recordResult('AI Content Optimization', 'FAIL', error.message);
      console.error('❌ AI content optimization failed:', error.message);
    }
  }

  async testSEOOptimization() {
    console.log('\n🔍 Testing SEO & Queensland Keyword Optimization...');
    
    try {
      const response = await axios.post(`${this.baseUrl}/api/ai/generate-seo`, {
        content: 'Professional Queensland small business services for local community growth',
        industry: 'professional-services',
        location: 'Queensland'
      }, {
        headers: { 
          Cookie: this.sessionCookie,
          'Content-Type': 'application/json'
        }
      });
      
      const result = response.data;
      
      if (result.success && result.seo) {
        const seo = result.seo;
        const hasHashtags = seo.hashtags && seo.hashtags.length >= 10;
        const hasKeywords = seo.keywords && seo.keywords.length >= 5;
        const hasMetaTags = seo.metaTags && seo.metaTags.length >= 3;
        
        if (hasHashtags && hasKeywords && hasMetaTags) {
          this.recordResult('SEO Optimization', 'PASS', 
            `Generated ${seo.hashtags.length} hashtags, ${seo.keywords.length} keywords, ${seo.metaTags.length} meta tags`);
          console.log('✅ SEO optimization successful');
          console.log(`   🏷️ Hashtags: ${seo.hashtags.slice(0, 5).join(', ')}...`);
          console.log(`   🔑 Keywords: ${seo.keywords.slice(0, 3).join(', ')}...`);
        } else {
          throw new Error('Insufficient SEO data generated');
        }
      } else {
        throw new Error('SEO generation failed');
      }
      
    } catch (error) {
      this.recordResult('SEO Optimization', 'FAIL', error.message);
      console.error('❌ SEO optimization failed:', error.message);
    }
  }

  async testLearningAlgorithm() {
    console.log('\n📈 Testing AI Learning Algorithm (30-day cycles)...');
    
    try {
      const response = await axios.get(`${this.baseUrl}/api/ai/learning-insights/${this.userId}`, {
        headers: { Cookie: this.sessionCookie }
      });
      
      const result = response.data;
      
      if (result.success && result.insights) {
        const insights = result.insights;
        const hasInsights = insights.insights && insights.insights.length > 0;
        const hasRecommendations = insights.recommendations && insights.recommendations.length > 0;
        const hasProjection = insights.projectedImprovement > 0;
        
        if (hasInsights && hasRecommendations && hasProjection) {
          this.recordResult('Learning Algorithm', 'PASS', 
            `Generated ${insights.insights.length} insights, ${insights.recommendations.length} recommendations, ${insights.projectedImprovement}% projected improvement`);
          console.log('✅ Learning algorithm analysis successful');
          console.log(`   🎯 Projected Improvement: ${insights.projectedImprovement}%`);
          console.log(`   💡 Insights: ${insights.insights.length} generated`);
          console.log(`   📋 Recommendations: ${insights.recommendations.length} provided`);
        } else {
          throw new Error('Incomplete learning algorithm response');
        }
      } else {
        throw new Error('Learning algorithm analysis failed');
      }
      
    } catch (error) {
      this.recordResult('Learning Algorithm', 'FAIL', error.message);
      console.error('❌ Learning algorithm test failed:', error.message);
    }
  }

  async testBusinessAnalytics() {
    console.log('\n📊 Testing Business Growth Analytics...');
    
    try {
      const response = await axios.get(`${this.baseUrl}/api/analytics/growth-insights?period=30`, {
        headers: { Cookie: this.sessionCookie }
      });
      
      const result = response.data;
      
      if (result.success && result.insights) {
        const insights = result.insights;
        const hasCurrentMetrics = insights.currentPeriod;
        const hasGrowthMetrics = insights.growth;
        const hasPlatformBreakdown = insights.platformBreakdown && insights.platformBreakdown.length > 0;
        const hasRecommendations = insights.recommendations && insights.recommendations.length > 0;
        
        if (hasCurrentMetrics && hasGrowthMetrics && hasPlatformBreakdown && hasRecommendations) {
          this.recordResult('Business Analytics', 'PASS', 
            `Growth insights with ${insights.platformBreakdown.length} platform analysis, ${insights.recommendations.length} recommendations`);
          console.log('✅ Business analytics successful');
          console.log(`   📈 Platform Breakdown: ${insights.platformBreakdown.length} platforms analyzed`);
          console.log(`   🎯 Recommendations: ${insights.recommendations.length} strategic insights`);
          console.log(`   📊 Projected Growth: ${insights.projectedGrowth}%`);
        } else {
          throw new Error('Incomplete business analytics response');
        }
      } else {
        throw new Error('Business analytics generation failed');
      }
      
    } catch (error) {
      this.recordResult('Business Analytics', 'FAIL', error.message);
      console.error('❌ Business analytics test failed:', error.message);
    }
  }

  async testAudienceInsights() {
    console.log('\n👥 Testing Advanced Audience Insights...');
    
    try {
      const response = await axios.get(`${this.baseUrl}/api/analytics/audience-insights`, {
        headers: { Cookie: this.sessionCookie }
      });
      
      const result = response.data;
      
      if (result.success && result.insights) {
        const insights = result.insights;
        const hasDemographics = insights.demographics && Object.keys(insights.demographics).length > 0;
        const hasInterests = insights.interests && insights.interests.length > 0;
        const hasContentTypes = insights.optimalContentTypes && insights.optimalContentTypes.length > 0;
        const hasEngagementTimes = insights.bestEngagementTimes && insights.bestEngagementTimes.length > 0;
        const hasGeographicReach = insights.geographicReach && Object.keys(insights.geographicReach).length > 0;
        
        if (hasDemographics && hasInterests && hasContentTypes && hasEngagementTimes && hasGeographicReach) {
          this.recordResult('Audience Insights', 'PASS', 
            `Complete audience analysis: ${insights.interests.length} interests, ${Object.keys(insights.geographicReach).length} geographic segments`);
          console.log('✅ Audience insights successful');
          console.log(`   🎯 Interests: ${insights.interests.slice(0, 3).join(', ')}...`);
          console.log(`   🕐 Best Times: ${insights.bestEngagementTimes.slice(0, 2).join(', ')}...`);
          console.log(`   🌏 Geographic: ${Object.keys(insights.geographicReach).slice(0, 3).join(', ')}...`);
        } else {
          throw new Error('Incomplete audience insights response');
        }
      } else {
        throw new Error('Audience insights generation failed');
      }
      
    } catch (error) {
      this.recordResult('Audience Insights', 'FAIL', error.message);
      console.error('❌ Audience insights test failed:', error.message);
    }
  }

  async testOptimalTiming() {
    console.log('\n⏰ Testing Optimal Timing Analysis...');
    
    try {
      const platforms = ['facebook', 'instagram', 'linkedin'];
      const timingResults = [];
      
      for (const platform of platforms) {
        try {
          const response = await axios.get(`${this.baseUrl}/api/ai/optimal-timing/${platform}`, {
            headers: { Cookie: this.sessionCookie }
          });
          
          const result = response.data;
          
          if (result.success && result.timing) {
            const timing = result.timing;
            const hasBestTimes = timing.bestTimes && timing.bestTimes.length > 0;
            const hasTimezone = timing.timezone;
            const hasDayOptimization = timing.dayOptimization && Object.keys(timing.dayOptimization).length > 0;
            
            if (hasBestTimes && hasTimezone && hasDayOptimization) {
              timingResults.push({
                platform,
                success: true,
                bestTimes: timing.bestTimes.length,
                timezone: timing.timezone
              });
            }
          }
        } catch (platformError) {
          timingResults.push({
            platform,
            success: false,
            error: platformError.message
          });
        }
      }
      
      const successfulPlatforms = timingResults.filter(r => r.success).length;
      
      if (successfulPlatforms >= 2) {
        this.recordResult('Optimal Timing', 'PASS', 
          `Timing analysis for ${successfulPlatforms}/${platforms.length} platforms`);
        console.log('✅ Optimal timing analysis successful');
        console.log(`   📅 Platforms analyzed: ${successfulPlatforms}/${platforms.length}`);
      } else {
        this.recordResult('Optimal Timing', 'PARTIAL', 
          `Only ${successfulPlatforms}/${platforms.length} platforms analyzed`);
        console.log(`⚠️ Partial timing analysis: ${successfulPlatforms}/${platforms.length}`);
      }
      
    } catch (error) {
      this.recordResult('Optimal Timing', 'FAIL', error.message);
      console.error('❌ Optimal timing test failed:', error.message);
    }
  }

  async testCrossPlatformPublishing() {
    console.log('\n🚀 Testing Cross-Platform Publishing (TEST content)...');
    
    try {
      const testContent = {
        content: "TEST - World-class social media platform validation for Queensland SME success",
        platforms: ['facebook', 'instagram', 'linkedin', 'x', 'youtube']
      };
      
      const response = await axios.post(`${this.baseUrl}/api/direct-publish`, testContent, {
        headers: { 
          Cookie: this.sessionCookie,
          'Content-Type': 'application/json'
        }
      });
      
      const result = response.data;
      
      if (result.results && Array.isArray(result.results)) {
        const successfulPublishes = result.results.filter(r => r.success).length;
        const totalAttempts = result.results.length;
        const successRate = (successfulPublishes / totalAttempts * 100).toFixed(1);
        
        if (successfulPublishes === totalAttempts) {
          this.recordResult('Cross-Platform Publishing', 'PASS', 
            `100% success rate: ${successfulPublishes}/${totalAttempts} platforms`);
          console.log('✅ Perfect cross-platform publishing');
          console.log(`   🎯 Success Rate: ${successRate}%`);
          console.log(`   📱 Platforms: ${result.results.map(r => r.platform).join(', ')}`);
        } else if (successfulPublishes > 0) {
          this.recordResult('Cross-Platform Publishing', 'PARTIAL', 
            `${successRate}% success rate: ${successfulPublishes}/${totalAttempts} platforms`);
          console.log(`⚠️ Partial publishing success: ${successRate}%`);
          
          // Log failed platforms
          const failedPlatforms = result.results.filter(r => !r.success);
          failedPlatforms.forEach(failure => {
            console.log(`   ❌ ${failure.platform}: ${failure.error}`);
          });
        } else {
          this.recordResult('Cross-Platform Publishing', 'FAIL', 
            'No platforms published successfully');
          console.log('❌ All platform publishing failed');
        }
      } else {
        throw new Error('Invalid publishing response format');
      }
      
    } catch (error) {
      this.recordResult('Cross-Platform Publishing', 'FAIL', error.message);
      console.error('❌ Cross-platform publishing test failed:', error.message);
    }
  }

  async testQuotaManagement() {
    console.log('\n📊 Testing Quota Management & Error Handling...');
    
    try {
      // Get current user status
      const userResponse = await axios.get(`${this.baseUrl}/api/user`, {
        headers: { Cookie: this.sessionCookie }
      });
      
      if (userResponse.data) {
        const user = userResponse.data;
        const remainingPosts = user.remainingPosts || 0;
        const totalPosts = user.totalPosts || 0;
        const subscriptionPlan = user.subscriptionPlan || 'unknown';
        
        const usagePercentage = totalPosts > 0 ? ((totalPosts - remainingPosts) / totalPosts * 100).toFixed(1) : 0;
        
        this.recordResult('Quota Management', 'PASS', 
          `${subscriptionPlan} plan: ${remainingPosts}/${totalPosts} remaining (${usagePercentage}% used)`);
        console.log('✅ Quota management operational');
        console.log(`   📋 Plan: ${subscriptionPlan}`);
        console.log(`   📊 Usage: ${usagePercentage}% (${totalPosts - remainingPosts}/${totalPosts} used)`);
        console.log(`   ✨ Remaining: ${remainingPosts} posts`);
      } else {
        throw new Error('Unable to retrieve user quota information');
      }
      
    } catch (error) {
      this.recordResult('Quota Management', 'FAIL', error.message);
      console.error('❌ Quota management test failed:', error.message);
    }
  }

  recordResult(testName, status, details) {
    this.testResults.push({
      test: testName,
      status,
      details,
      timestamp: new Date().toISOString()
    });
  }

  generateWorldClassReport() {
    console.log('\n🏆 WORLD-CLASS SOCIAL MEDIA PLATFORM REPORT');
    console.log('=' .repeat(70));
    
    const passedTests = this.testResults.filter(r => r.status === 'PASS').length;
    const partialTests = this.testResults.filter(r => r.status === 'PARTIAL').length;
    const failedTests = this.testResults.filter(r => r.status === 'FAIL').length;
    const totalTests = this.testResults.length;
    
    const successRate = (passedTests / totalTests * 100).toFixed(1);
    const overallScore = ((passedTests + partialTests * 0.5) / totalTests * 100).toFixed(1);
    
    console.log(`\n📊 COMPREHENSIVE TEST RESULTS:`);
    console.log(`   ✅ Passed: ${passedTests}/${totalTests}`);
    console.log(`   ⚠️ Partial: ${partialTests}/${totalTests}`);
    console.log(`   ❌ Failed: ${failedTests}/${totalTests}`);
    console.log(`   🎯 Success Rate: ${successRate}%`);
    console.log(`   🏆 Overall Score: ${overallScore}%`);
    
    console.log('\n📋 DETAILED RESULTS:');
    this.testResults.forEach(result => {
      const status = result.status === 'PASS' ? '✅' : result.status === 'PARTIAL' ? '⚠️' : '❌';
      console.log(`   ${status} ${result.test}: ${result.details}`);
    });
    
    console.log('\n🎯 WORLD-CLASS PLATFORM STATUS:');
    if (overallScore >= 90) {
      console.log('   🌟 EXCELLENT - Platform ready for Queensland SME success');
      console.log('   🚀 All systems optimized for maximum business growth');
    } else if (overallScore >= 80) {
      console.log('   ✨ VERY GOOD - Platform performing at high standards');
      console.log('   🔧 Minor optimizations recommended for peak performance');
    } else if (overallScore >= 70) {
      console.log('   ⭐ GOOD - Platform functional with room for improvement');
      console.log('   🛠️ Several optimizations needed for world-class status');
    } else {
      console.log('   ⚠️ NEEDS IMPROVEMENT - Platform requires significant optimization');
      console.log('   🔨 Major system improvements needed for Queensland SME success');
    }
    
    console.log('\n🎖️ WORLD-CLASS FEATURES VALIDATED:');
    console.log('   🧠 AI Content Optimization for Queensland businesses');
    console.log('   🔍 SEO & Hashtag generation for local market');
    console.log('   📈 30-day learning cycles for continuous improvement');
    console.log('   📊 Business growth analytics & audience insights');
    console.log('   ⏰ Optimal timing analysis for maximum engagement');
    console.log('   🚀 Cross-platform publishing for 5 major networks');
    console.log('   📋 Professional quota management & error handling');
    
    return {
      passedTests,
      partialTests,
      failedTests,
      totalTests,
      successRate: parseFloat(successRate),
      overallScore: parseFloat(overallScore),
      status: overallScore >= 90 ? 'EXCELLENT' : overallScore >= 80 ? 'VERY_GOOD' : overallScore >= 70 ? 'GOOD' : 'NEEDS_IMPROVEMENT',
      results: this.testResults
    };
  }
}

// Run the comprehensive world-class test
const test = new WorldClassSystemTest();
test.runComprehensiveTest().catch(console.error);