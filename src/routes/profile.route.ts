import express from "express";
import { protect } from "../controllers/auth.controller";
import { getProfile } from "../controllers/profile.controller";

const router = express.Router();

router.get("/", protect, getProfile);

export default router;
