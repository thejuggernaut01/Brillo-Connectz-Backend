import express from "express";
import {
  changePassword,
  updateUsername,
} from "../controllers/settings.controller";
import { protect } from "../controllers/auth.controller";

const router = express.Router();

router.patch("/change-password", protect, changePassword);

router.patch("/update-username", protect, updateUsername);

export default router;
