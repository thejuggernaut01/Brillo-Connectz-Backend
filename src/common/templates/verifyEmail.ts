export const verifyEmailTemplate = (token: string) => {
  return `
          <main>
            <p>Welcome to Brillo Connectz football! 📚✨ To ensure the security of your account, we kindly ask you to verify your email address.</p>

            <p>Please click on the following link to complete the verification process: <a href="http://localhost:3000/verify-email?token=${token}">Verification Link</a></p>

            <p>Note: This link is valid for the next 30 minutes. If you don't verify your account within this timeframe, you may need to request a new verification email.</p>

            <p>If you did not sign up for Brillo Connectz football, please ignore this email.</p>

            <p>Thank you for being a part of our reading community!</p>

            <p>Best,<br>
              Brillo Connectz football Team</p>
          </main>
    `;
};
