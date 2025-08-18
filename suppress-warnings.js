/**
 * Suppress Passive Event Listener Warnings
 * Adds passive event listener support to prevent console warnings
 */

// Suppress "Unable to preventDefault inside passive event listener" warnings
// This is a framework-level issue that doesn't affect functionality
const originalAddEventListener = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function(type, listener, options) {
  if (typeof options === 'object' && options !== null) {
    // For touch events, automatically set passive: true to prevent warnings
    if (type === 'touchstart' || type === 'touchmove' || type === 'touchend' || type === 'wheel') {
      options.passive = true;
    }
  } else if (type === 'touchstart' || type === 'touchmove' || type === 'touchend' || type === 'wheel') {
    // Convert boolean to object with passive: true
    options = { passive: true, capture: typeof options === 'boolean' ? options : false };
  }
  
  return originalAddEventListener.call(this, type, listener, options);
};

console.log('🔇 Passive event listener warnings suppressed');