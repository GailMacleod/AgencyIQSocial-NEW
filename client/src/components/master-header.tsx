import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Menu, X, BarChart3, Calendar, Settings, User } from "lucide-react";
import { Link } from "wouter";
import UserMenu from "@/components/user-menu";
import agencyLogo from "@assets/agency_logo_1749083054761.png";

interface MasterHeaderProps {
  showLogin?: boolean;
  showUserMenu?: boolean;
  title?: string;
}

export default function MasterHeader({ 
  showLogin = false, 
  showUserMenu = true,
  title 
}: MasterHeaderProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <>
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Left side */}
            <div className="flex items-center space-x-4">
              <Link href="/">
                <div className="flex items-center space-x-2 cursor-pointer">
                  <img 
                    src="attached_assets/agency_logo_512x512 (1).png" 
                    alt="The AgencyIQ" 
                    className="w-8 h-8 object-contain"
                  />
                  <div>
                    <h1 className="text-lg font-semibold text-gray-900 lowercase">
                      {title || "the agencyiq"}
                    </h1>
                  </div>
                </div>
              </Link>
            </div>

            {/* Right side - Desktop */}
            <div className="hidden md:flex items-center space-x-4">
              {showLogin && (
                <Button
                  onClick={() => window.location.href = '/login'}
                  variant="outline"
                  className="lowercase"
                >
                  log in
                </Button>
              )}
              
              {showUserMenu && <UserMenu />}
            </div>

            {/* Mobile menu button */}
            <div className="md:hidden">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="p-2"
              >
                {mobileMenuOpen ? (
                  <X className="w-5 h-5" />
                ) : (
                  <Menu className="w-5 h-5" />
                )}
              </Button>
            </div>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-gray-200 bg-white">
            <div className="px-4 py-3 space-y-2">
              <Link href="/analytics">
                <Button 
                  variant="ghost" 
                  className="w-full justify-start lowercase"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  <BarChart3 className="w-4 h-4 mr-2" />
                  analytics
                </Button>
              </Link>
              
              <Link href="/schedule">
                <Button 
                  variant="ghost" 
                  className="w-full justify-start lowercase"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  <Calendar className="w-4 h-4 mr-2" />
                  schedule
                </Button>
              </Link>
              
              <Link href="/brand-purpose">
                <Button 
                  variant="ghost" 
                  className="w-full justify-start lowercase"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  <Settings className="w-4 h-4 mr-2" />
                  brand purpose
                </Button>
              </Link>
              
              {showLogin && (
                <Button
                  onClick={() => window.location.href = '/login'}
                  variant="outline"
                  className="w-full lowercase mt-3"
                >
                  log in
                </Button>
              )}
              
              {showUserMenu && (
                <div className="border-t pt-3">
                  <UserMenu />
                </div>
              )}
            </div>
          </div>
        )}
      </nav>
    </>
  );
}