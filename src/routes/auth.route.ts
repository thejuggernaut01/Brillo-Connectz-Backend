import express from "express";

import {
  create,
  verifyEmail,
  login,
  protect,
} from "../controllers/auth.controller";

const router = express.Router();

router.post("/create", create);
router.post("/login", login);
router.post("/verify-email", verifyEmail);

router.use(protect);

router.get("/test", (req, res) => {
  res.send("Authentication route!");
});

export default router;
