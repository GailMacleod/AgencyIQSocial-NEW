import React from 'react';
import { ScheduleManager } from '@/components/ScheduleManager';
import MasterHeader from '@/components/master-header';
import MasterFooter from '@/components/master-footer';
import BackButton from '@/components/back-button';

export default function QuotaSchedule() {
  return (
    <div className="min-h-screen bg-gray-50">
      <MasterHeader showUserMenu={true} />
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <BackButton to="/brand-purpose" label="Back to Brand Purpose" />
        </div>
        
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Content Schedule Manager
          </h1>
          <p className="text-lg text-gray-600">
            Strict quota enforcement with 30-day rolling periods for Queensland businesses
          </p>
        </div>

        <ScheduleManager />
      </div>
      
      <MasterFooter />
    </div>
  );
}