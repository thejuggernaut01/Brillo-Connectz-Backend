import express from "express";

import {
  create,
  verifyEmail,
  login,
  protect,
  resendEmail,
  forgotPassword,
  updatePassword,
  logout,
} from "../controllers/auth.controller";
import validate from "../common/schemas/validate";
import {
  forgotPasswordSchema,
  createAccountSchema,
  resendEmailSchema,
  verifyEmailSchema,
  updatePasswordSchema,
  loginSchema,
} from "../common/schemas/auth/authSchema";

const router = express.Router();

router.post("/create", validate(createAccountSchema), create);
router.post("/resend-email", validate(resendEmailSchema), resendEmail);
router.post("/verify-email", validate(verifyEmailSchema), verifyEmail);
router.post("/forgot-password", validate(forgotPasswordSchema), forgotPassword);
router.patch(
  "/update-password",
  validate(updatePasswordSchema),
  updatePassword
);

router.post("/login", validate(loginSchema), login);
router.post("/logout", logout);
router.use(protect);

router.get("/test", (req, res) => {
  res.send("Authentication route!");
});

export default router;
