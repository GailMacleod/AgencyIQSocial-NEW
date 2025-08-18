import sgMail from '@sendgrid/mail';

export interface NotificationData {
  userId: string;
  email: string;
  type: 'quota_low' | 'video_approved' | 'subscription_activated' | 'payment_failed';
  content: string;
  metadata?: any;
}

export const sendNotification = async (data: NotificationData): Promise<boolean> => {
  try {
    if (!process.env.SENDGRID_API_KEY) {
      console.log('⚠️ SendGrid not configured - notification skipped');
      return false;
    }

    const subjects = {
      quota_low: 'Quota Warning - TheAgencyIQ',
      video_approved: 'Video Approved - TheAgencyIQ',
      subscription_activated: 'Welcome to TheAgencyIQ!',
      payment_failed: 'Payment Issue - TheAgencyIQ'
    };

    const msg = {
      to: data.email,
      from: process.env.SENDGRID_FROM_EMAIL || 'no-reply@theagencyiq.ai',
      subject: subjects[data.type],
      text: data.content,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>TheAgencyIQ Notification</h2>
          <p>${data.content}</p>
          <hr>
          <p style="color: #666; font-size: 12px;">
            This is an automated message from TheAgencyIQ.
          </p>
        </div>
      `
    };

    await sgMail.send(msg);
    console.log(`✅ Notification sent to ${data.email}: ${data.type}`);
    return true;
  } catch (error: any) {
    console.error('SendGrid notification error:', error);
    return false;
  }
};

// Helper function to send quota warnings
export const sendQuotaWarning = async (userId: string, email: string, remaining: number, total: number) => {
  const percentage = Math.round((remaining / total) * 100);
  const content = `Your social media post quota is running low. You have ${remaining} posts remaining out of ${total} (${percentage}% left). Consider upgrading your plan to continue posting.`;
  
  return sendNotification({
    userId,
    email,
    type: 'quota_low',
    content,
    metadata: { remaining, total, percentage }
  });
};

// Helper function to send video approval notifications
export const sendVideoApproval = async (userId: string, email: string, postId: string) => {
  const content = `Your video has been approved and is ready for publishing! Post ID: ${postId}`;
  
  return sendNotification({
    userId,
    email,
    type: 'video_approved',
    content,
    metadata: { postId }
  });
};