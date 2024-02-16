import { smtpexpressClient } from "../../config/emailConfig";
import { welcomeEmailTemplate } from "./../../templates/welcomeEmail";

const welcomeEmail = async (email: string) => {
  const response = await smtpexpressClient.sendApi.sendMail({
    subject: "A message from the express",
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
