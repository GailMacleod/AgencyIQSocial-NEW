// Beacon.js - Analytics and tracking
console.log('Beacon.js loaded successfully');

// Initialize tracking
window.beacon = {
  track: function(event, data) {
    console.log('Tracking event:', event, data);
  },
  init: function() {
    console.log('Beacon tracking initialized');
  }
};

// Auto-initialize
if (typeof window !== 'undefined') {
  window.beacon.init();
}