import express from "express";
import {
  changePassword,
  updateEmail,
  updateUsername,
} from "../controllers/settings.controller";
import { protect } from "../controllers/auth.controller";

const router = express.Router();

router.patch("/change-password", protect, changePassword);

router.patch("/update-username", protect, updateUsername);

router.patch("/change-email", protect, updateEmail);

export default router;
