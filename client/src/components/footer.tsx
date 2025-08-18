export default function Footer() {
  return (
    <footer className="bg-white border-t border-gray-200 py-8 mt-16">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center space-y-4">
          <div className="flex flex-col sm:flex-row justify-center items-center gap-4 text-sm">
            <a 
              href="https://theagencyiq.ai/privacy-policy" 
              className="text-gray-600 hover:text-gray-900 transition-colors"
              target="_blank"
              rel="noopener noreferrer"
            >
              Privacy Policy
            </a>
            <span className="hidden sm:block text-gray-300">•</span>
            <a 
              href="https://theagencyiq.ai/terms-of-service" 
              className="text-gray-600 hover:text-gray-900 transition-colors"
              target="_blank"
              rel="noopener noreferrer"
            >
              Terms and Conditions
            </a>
            <span className="hidden sm:block text-gray-300">•</span>
            <a 
              href="mailto:support@theagencyiq.ai" 
              className="text-gray-600 hover:text-gray-900 transition-colors"
            >
              Contact Support
            </a>
          </div>
          <p className="text-sm text-gray-500">
            © 2025 MacleodGlobal T/A The AgencyIQ. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}
