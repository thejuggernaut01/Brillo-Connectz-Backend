import express from "express";

import {
  create,
  verifyEmail,
  login,
  protect,
  resendEmail,
  forgotPassword,
  updatePassword,
} from "../controllers/auth.controller";

const router = express.Router();

router.post("/create", create);
router.post("/resend-email", resendEmail);
router.post("/verify-email", verifyEmail);
router.post("/forgot-password", forgotPassword);
router.post("/update-password", updatePassword);

router.post("/login", login);
router.use(protect);

router.get("/test", (req, res) => {
  res.send("Authentication route!");
});

export default router;
