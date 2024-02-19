import express from "express";
import {
  changePassword,
  updateEmail,
  updateUsername,
} from "../controllers/settings.controller";
import { protect } from "../controllers/auth.controller";
import validate from "../common/schemas/validate";
import {
  changePasswordSchema,
  updateUsernameSchema,
  changeEmailSchema,
} from "../common/schemas/settings/settingsSchema";

const router = express.Router();

router.patch(
  "/change-password",
  protect,
  validate(changePasswordSchema),
  changePassword
);

router.patch(
  "/update-username",
  protect,
  validate(updateUsernameSchema),
  updateUsername
);

router.patch(
  "/change-email",
  protect,
  validate(changeEmailSchema),
  updateEmail
);

export default router;
