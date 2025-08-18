// Queensland and Australian local calendar events for content optimisation
export interface LocalEvent {
  date: string;
  name: string;
  type: 'holiday' | 'business' | 'cultural' | 'seasonal' | 'sporting';
  impact: 'high' | 'medium' | 'low';
  description: string;
  hashtags: string[];
  contentSuggestions: string[];
}

export const queenslandEvents2025: LocalEvent[] = [
  // January
  {
    date: '2025-01-01',
    name: 'New Year\'s Day',
    type: 'holiday',
    impact: 'high',
    description: 'National public holiday - fresh starts and resolutions',
    hashtags: ['#NewYear', '#FreshStart', '#Queensland', '#Goals2025'],
    contentSuggestions: ['New year business goals', 'Fresh start messaging', 'Goal-setting content']
  },
  {
    date: '2025-01-26',
    name: 'Australia Day',
    type: 'holiday',
    impact: 'high',
    description: 'National celebration - perfect for local pride content',
    hashtags: ['#AustraliaDay', '#Queensland', '#LocalPride', '#Community'],
    contentSuggestions: ['Local business pride', 'Community celebration', 'Australian values']
  },
  
  // February
  {
    date: '2025-02-14',
    name: 'Valentine\'s Day',
    type: 'cultural',
    impact: 'medium',
    description: 'Romance and relationships - good for customer appreciation',
    hashtags: ['#ValentinesDay', '#CustomerLove', '#Queensland'],
    contentSuggestions: ['Customer appreciation', 'Love your business', 'Relationship building']
  },
  
  // March
  {
    date: '2025-03-08',
    name: 'International Women\'s Day',
    type: 'cultural',
    impact: 'medium',
    description: 'Celebrating women in business and leadership',
    hashtags: ['#IWD2025', '#WomenInBusiness', '#Queensland', '#Leadership'],
    contentSuggestions: ['Women business leaders', 'Female empowerment', 'Diversity celebration']
  },
  {
    date: '2025-03-17',
    name: 'St. Patrick\'s Day',
    type: 'cultural',
    impact: 'low',
    description: 'Irish celebration - community and luck themes',
    hashtags: ['#StPatricksDay', '#LuckOfTheIrish', '#Queensland'],
    contentSuggestions: ['Lucky business moments', 'Green initiatives', 'Community celebration']
  },
  
  // April
  {
    date: '2025-04-18',
    name: 'Good Friday',
    type: 'holiday',
    impact: 'high',
    description: 'Easter long weekend begins - family and reflection time',
    hashtags: ['#Easter', '#Family', '#Queensland', '#LongWeekend'],
    contentSuggestions: ['Family business values', 'Reflection and gratitude', 'Community support']
  },
  {
    date: '2025-04-21',
    name: 'Easter Monday',
    type: 'holiday',
    impact: 'high',
    description: 'End of Easter long weekend - renewal themes',
    hashtags: ['#EasterMonday', '#Renewal', '#Queensland'],
    contentSuggestions: ['New beginnings', 'Spring renewal', 'Fresh opportunities']
  },
  {
    date: '2025-04-25',
    name: 'ANZAC Day',
    type: 'holiday',
    impact: 'high',
    description: 'Remembrance and national pride - respect and community',
    hashtags: ['#ANZACDay', '#LestWeForget', '#Queensland', '#Respect'],
    contentSuggestions: ['Honoring sacrifice', 'Community respect', 'National values']
  },
  
  // May
  {
    date: '2025-05-05',
    name: 'Labour Day (QLD)',
    type: 'holiday',
    impact: 'high',
    description: 'Queensland Labour Day - workers and business achievement',
    hashtags: ['#LabourDay', '#Queensland', '#Workers', '#Achievement'],
    contentSuggestions: ['Worker appreciation', 'Business achievements', 'Team recognition']
  },
  {
    date: '2025-05-11',
    name: 'Mother\'s Day',
    type: 'cultural',
    impact: 'high',
    description: 'Celebrating mothers and nurturing - perfect for appreciation content',
    hashtags: ['#MothersDay', '#Appreciation', '#Queensland', '#Family'],
    contentSuggestions: ['Customer appreciation', 'Nurturing business relationships', 'Family values']
  },
  
  // June
  {
    date: '2025-06-09',
    name: 'Queen\'s Birthday (QLD)',
    type: 'holiday',
    impact: 'medium',
    description: 'Queensland Queen\'s Birthday holiday - tradition and celebration',
    hashtags: ['#QueensBirthday', '#Queensland', '#Tradition'],
    contentSuggestions: ['Business traditions', 'Celebrating milestones', 'Royal service']
  },
  {
    date: '2025-06-21',
    name: 'Winter Solstice',
    type: 'seasonal',
    impact: 'low',
    description: 'Beginning of winter - cozy and warm themes',
    hashtags: ['#WinterSolstice', '#Queensland', '#Winter', '#Cozy'],
    contentSuggestions: ['Winter comfort', 'Staying warm', 'Seasonal services']
  },
  
  // July
  {
    date: '2025-07-01',
    name: 'New Financial Year',
    type: 'business',
    impact: 'high',
    description: 'Start of Australian financial year - perfect for business planning',
    hashtags: ['#NewFinancialYear', '#BusinessPlanning', '#Queensland'],
    contentSuggestions: ['Financial planning', 'Business goals', 'New year strategies']
  },
  
  // August
  {
    date: '2025-08-16',
    name: 'Queensland Day',
    type: 'cultural',
    impact: 'high',
    description: 'Celebrating Queensland - perfect for local business pride',
    hashtags: ['#QueenslandDay', '#LocalPride', '#Queensland', '#BeautifulOneDay'],
    contentSuggestions: ['Queensland business pride', 'Local community', 'State celebration']
  },
  
  // September
  {
    date: '2025-09-01',
    name: 'Spring Day',
    type: 'seasonal',
    impact: 'medium',
    description: 'Beginning of spring - growth and renewal themes',
    hashtags: ['#Spring', '#Growth', '#Queensland', '#Renewal'],
    contentSuggestions: ['Business growth', 'New opportunities', 'Fresh starts']
  },
  {
    date: '2025-09-23',
    name: 'Spring Equinox',
    type: 'seasonal',
    impact: 'low',
    description: 'Balance and new beginnings',
    hashtags: ['#SpringEquinox', '#Balance', '#Queensland'],
    contentSuggestions: ['Work-life balance', 'New season opportunities', 'Growth planning']
  },
  
  // October
  {
    date: '2025-10-06',
    name: 'Labour Day (NSW/ACT/SA)',
    type: 'business',
    impact: 'medium',
    description: 'Interstate labour day - worker appreciation',
    hashtags: ['#LabourDay', '#Workers', '#BusinessSuccess'],
    contentSuggestions: ['Team appreciation', 'Hard work recognition', 'Business achievements']
  },
  {
    date: '2025-10-31',
    name: 'Halloween',
    type: 'cultural',
    impact: 'medium',
    description: 'Fun and creative - great for engaging content',
    hashtags: ['#Halloween', '#Fun', '#Creative', '#Queensland'],
    contentSuggestions: ['Creative business solutions', 'Fun workplace culture', 'Seasonal promotions']
  },
  
  // November
  {
    date: '2025-11-04',
    name: 'Melbourne Cup Day',
    type: 'sporting',
    impact: 'high',
    description: 'The race that stops the nation - celebration and excitement',
    hashtags: ['#MelbourneCup', '#RaceThatStopsTheNation', '#Queensland'],
    contentSuggestions: ['Winning business strategies', 'Racing ahead', 'Celebration content']
  },
  {
    date: '2025-11-11',
    name: 'Remembrance Day',
    type: 'cultural',
    impact: 'medium',
    description: 'Remembering and honoring - respect and reflection',
    hashtags: ['#RemembranceDay', '#LestWeForget', '#Respect'],
    contentSuggestions: ['Honoring commitments', 'Remembering values', 'Respectful business']
  },
  
  // December
  {
    date: '2025-12-01',
    name: 'Summer Begin',
    type: 'seasonal',
    impact: 'medium',
    description: 'Queensland summer begins - energy and activity',
    hashtags: ['#Summer', '#Queensland', '#Energy', '#Activity'],
    contentSuggestions: ['High energy content', 'Summer business boost', 'Active engagement']
  },
  {
    date: '2025-12-21',
    name: 'Summer Solstice',
    type: 'seasonal',
    impact: 'low',
    description: 'Longest day - peak energy and brightness',
    hashtags: ['#SummerSolstice', '#PeakEnergy', '#Queensland'],
    contentSuggestions: ['Peak performance', 'Bright future', 'Maximum impact']
  },
  {
    date: '2025-12-25',
    name: 'Christmas Day',
    type: 'holiday',
    impact: 'high',
    description: 'Christmas celebration - gratitude and giving',
    hashtags: ['#Christmas', '#Gratitude', '#Queensland', '#Giving'],
    contentSuggestions: ['Customer gratitude', 'Year-end appreciation', 'Giving back']
  },
  {
    date: '2025-12-26',
    name: 'Boxing Day',
    type: 'holiday',
    impact: 'high',
    description: 'Boxing Day sales and family time',
    hashtags: ['#BoxingDay', '#Queensland', '#Family'],
    contentSuggestions: ['Special offers', 'Family business values', 'Year-end celebration']
  }
];

// Get optimal posting times based on Queensland business patterns
export const getOptimalPostingTimes = (platform: string): string[] => {
  const times: { [key: string]: string[] } = {
    facebook: ['8:00 AM', '12:00 PM', '6:00 PM'],
    instagram: ['7:00 AM', '11:00 AM', '5:00 PM'],
    linkedin: ['8:00 AM', '12:00 PM', '5:00 PM'],
    x: ['9:00 AM', '1:00 PM', '7:00 PM'],
    youtube: ['6:00 PM', '8:00 PM']
  };
  
  return times[platform.toLowerCase()] || ['9:00 AM', '1:00 PM', '6:00 PM'];
};

// Get relevant events for a date range
export const getEventsForDateRange = (startDate: string, endDate: string): LocalEvent[] => {
  const start = new Date(startDate);
  const end = new Date(endDate);
  
  return queenslandEvents2025.filter(event => {
    const eventDate = new Date(event.date);
    return eventDate >= start && eventDate <= end;
  });
};

// Get event impact score for scheduling optimization
export const getEventImpactScore = (date: string): number => {
  const event = queenslandEvents2025.find(e => e.date === date);
  if (!event) return 0;
  
  switch (event.impact) {
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0;
  }
};

// Check if date is a Queensland public holiday
export const isQueenslandHoliday = (date: string): boolean => {
  const event = queenslandEvents2025.find(e => e.date === date);
  return event?.type === 'holiday' || false;
};

// Get content suggestions for a specific date
export const getContentSuggestionsForDate = (date: string): string[] => {
  const event = queenslandEvents2025.find(e => e.date === date);
  return event?.contentSuggestions || [];
};

// Get relevant hashtags for a date
export const getHashtagsForDate = (date: string): string[] => {
  const event = queenslandEvents2025.find(e => e.date === date);
  return event?.hashtags || ['#Queensland', '#BusinessGrowth'];
};