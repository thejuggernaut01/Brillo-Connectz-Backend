import { createClient } from "smtpexpress";

export const smtpexpressClient = createClient({
  projectId: process.env.SMTP_PROJECT_ID,
  projectSecret: process.env.SMTP_PROJECT_SECRET,
});
