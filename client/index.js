// Schedule page mobile layout detection and logging
if (window.matchMedia('(max-width: 768px)').matches) {
  console.log('Schedule layout adjusted for mobile');
  
  // Monitor generate buttons for responsiveness
  const checkButtonResponsiveness = () => {
    const generateButtons = document.querySelectorAll('.generate-button');
    generateButtons.forEach(button => {
      button.addEventListener('click', () => {
        if (!button.offsetParent || button.disabled) {
          console.log('Reverting schedule layout');
        }
      });
    });
  };
  
  // Check when DOM is loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkButtonResponsiveness);
  } else {
    checkButtonResponsiveness();
  }
}