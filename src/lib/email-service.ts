import type { Env } from "../config.js";
import { env as defaultEnv } from "../config.js";

export interface SendVerificationEmailOptions {
  to: string;
  name: string;
  token: string;
  verificationUrl: string;
}

export interface EmailResult {
  delivered: boolean;
  provider: string;
  previewUrl?: string;
}

export interface EmailService {
  readonly provider: string;
  sendVerificationEmail(options: SendVerificationEmailOptions): Promise<EmailResult>;
}

export class DevelopmentEmailService implements EmailService {
  readonly provider = "development";

  async sendVerificationEmail(options: SendVerificationEmailOptions): Promise<EmailResult> {
    // In development and test mode, we do not pretend external delivery occurred.
    // We log the direct URL for manual testing or developer convenience.
    console.info(
      "\n==================== [SENTINELSCAN EMAIL SERVICE (DEV)] ====================\n" +
        `To: ${options.to} (${options.name})\n` +
        `Subject: Verify your SentinelScan workspace account\n` +
        `Verification Link: ${options.verificationUrl}\n` +
        "Notice: Running in development mode. No external email was dispatched.\n" +
        "============================================================================\n",
    );

    return {
      delivered: false,
      provider: "development",
      previewUrl: options.verificationUrl,
    };
  }
}

export class ResendEmailService implements EmailService {
  readonly provider = "resend";
  private readonly apiKey: string;
  private readonly from: string;

  constructor(apiKey: string, from: string) {
    this.apiKey = apiKey;
    this.from = from;
  }

  async sendVerificationEmail(options: SendVerificationEmailOptions): Promise<EmailResult> {
    const htmlBody = `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 32px 20px; color: #111827;">
        <h2 style="font-size: 20px; font-weight: 600; margin-bottom: 16px;">Verify your SentinelScan account</h2>
        <p style="font-size: 14px; line-height: 1.6; color: #4B5563;">Hello ${options.name},</p>
        <p style="font-size: 14px; line-height: 1.6; color: #4B5563;">
          Thank you for signing up for SentinelScan. Please click the button below to verify your email address and activate your workspace.
        </p>
        <div style="margin: 28px 0;">
          <a href="${options.verificationUrl}" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-size: 14px; font-weight: 500; display: inline-block;">
            Verify Email Address
          </a>
        </div>
        <p style="font-size: 13px; line-height: 1.5; color: #6B7280;">
          Or copy and paste this link into your browser:<br />
          <a href="${options.verificationUrl}" style="color: #2563eb; word-break: break-all;">${options.verificationUrl}</a>
        </p>
        <p style="font-size: 12px; line-height: 1.5; color: #9CA3AF; margin-top: 32px; border-top: 1px solid #E5E7EB; padding-top: 16px;">
          This link will expire in 24 hours. If you did not create a SentinelScan account, you can safely ignore this email.
        </p>
      </div>
    `;

    const textBody = `Hello ${options.name},\n\nPlease verify your email address to activate your SentinelScan workspace:\n${options.verificationUrl}\n\nThis link will expire in 24 hours.\nIf you did not request this, please ignore this email.`;

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: this.from,
        to: [options.to],
        subject: "Verify your SentinelScan account",
        html: htmlBody,
        text: textBody,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[Email Service] Failed to send email via Resend: ${response.status} - ${errorText}`);
      throw new Error("Failed to deliver verification email through email provider.");
    }

    return {
      delivered: true,
      provider: "resend",
    };
  }
}

export function createEmailService(config: Env = defaultEnv): EmailService {
  const resendApiKey = config.RESEND_API_KEY || config.EMAIL_API_KEY;
  if ((config.EMAIL_PROVIDER === "resend" || Boolean(config.RESEND_API_KEY)) && resendApiKey) {
    return new ResendEmailService(resendApiKey, config.EMAIL_FROM);
  }

  return new DevelopmentEmailService();
}

export const defaultEmailService = createEmailService();
