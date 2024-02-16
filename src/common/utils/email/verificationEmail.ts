import { smtpexpressClient } from "../../config/emailConfig";
import { verifyEmailTemplate } from "../../templates/verifyEmail";
import User from "../../../models/user.model";

const verificationEmail = async (email: string, token: string) => {
  await User.findOneAndUpdate(
    { email },
    {
      isVerified: false,
      verificationToken: token,
      verificationEmailExpiration: Date.now() + 1800000,
    }
  );

  const response = await smtpexpressClient.sendApi.sendMail({
    subject: "A message from the express",
    message: verifyEmailTemplate(token),
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

export default verificationEmail;
