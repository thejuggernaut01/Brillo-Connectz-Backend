import { smtpexpressClient } from "../../config/emailConfig";
import { welcomeEmailTemplate } from "./../../templates/welcomeEmail";

const welcomeEmail = async (email: string) => {
  const response = await smtpexpressClient.sendApi.sendMail({
    subject: "Welcome to Brillo Connectz Football",
    message: welcomeEmailTemplate(email),
    sender: {
      name: "Brillo Football",
      email: process.env.SMTP_SENDER_ADDRESS,
    },
    recipients: {
      name: email,
      email: email,
    },
  });

  return response;
};

export default welcomeEmail;
