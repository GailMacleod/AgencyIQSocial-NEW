export default function MasterFooter() {
  return (
    <footer className="bg-white border-t border-gray-100 mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="text-center space-y-4">
          <div className="flex justify-center items-center space-x-6 text-sm text-gray-500">
            <a href="https://theagencyiq.ai/terms-and-conditions" target="_blank" rel="noopener noreferrer" className="hover:text-gray-700 transition-colors">
              Terms of Service
            </a>
            <span>•</span>
            <a href="https://theagencyiq.ai/privacy-policy" target="_blank" rel="noopener noreferrer" className="hover:text-gray-700 transition-colors">
              Privacy Policy
            </a>
            <span>•</span>
            <a href="mailto:support@theagencyiq.ai" className="hover:text-gray-700 transition-colors">
              Contact Support
            </a>
          </div>
          <p className="text-sm text-gray-400">
            © 2024 MacleodGlobal trading as The AgencyIQ. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}