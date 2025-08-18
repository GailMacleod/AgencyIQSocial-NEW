// Mock beacon.js file for Replit compatibility
// This file prevents 403 errors from external beacon.js requests

(function() {
  'use strict';
  
  // Mock beacon functionality - no-op implementation
  window.replitBeacon = {
    init: function() {
      // Mock initialization
      console.log('Beacon initialized (mock)');
    },
    track: function(event, data) {
      // Mock event tracking
      console.log('Beacon track (mock):', event, data);
    }
  };
  
  // Auto-initialize if needed
  if (typeof window.replitBeaconInit === 'function') {
    window.replitBeaconInit();
  }
})();