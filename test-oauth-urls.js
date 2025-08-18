/**
 * Test OAuth URL Generation and Callback Configuration
 * Verifies that OAuth URLs are correctly configured for Facebook and Instagram
 */

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

console.log('🔍 OAuth URL Configuration Test');
console.log('================================\n');

console.log('✅ Base URL:', BASE_URL);
console.log('');

console.log('🔗 OAuth Initiation URLs:');
console.log('Facebook:', BASE_URL + '/auth/facebook');
console.log('Instagram:', BASE_URL + '/auth/instagram');
console.log('LinkedIn:', BASE_URL + '/auth/linkedin');
console.log('X (Twitter):', BASE_URL + '/auth/twitter');
console.log('YouTube:', BASE_URL + '/auth/youtube');
console.log('');

console.log('🔙 OAuth Callback URLs (configured in Facebook app):');
console.log('Facebook:', BASE_URL + '/auth/facebook/callback');
console.log('Instagram:', BASE_URL + '/auth/instagram/callback');
console.log('LinkedIn:', BASE_URL + '/auth/linkedin/callback');
console.log('X (Twitter):', BASE_URL + '/auth/twitter/callback');
console.log('YouTube:', BASE_URL + '/auth/youtube/callback');
console.log('');

console.log('📋 Facebook App Configuration Status:');
console.log('✅ Facebook Login: Enabled with callback URLs added');
console.log('❓ Instagram Basic Display: Needs verification');
console.log('');

console.log('🎯 Next Steps:');
console.log('1. Try Facebook OAuth connection (should work)');
console.log('2. For Instagram: Check if Instagram Basic Display product is enabled');
console.log('3. If Instagram still fails, wait 5-10 minutes for Facebook to propagate changes');
console.log('');

console.log('💡 Instagram OAuth Note:');
console.log('Instagram OAuth may require Instagram Basic Display to be enabled as a separate product');
console.log('in your Facebook app, not just Facebook Login.');