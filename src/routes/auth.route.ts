import express from "express";

import { create, login, protect } from "../controllers/auth.controller";

const router = express.Router();

router.post("/create", create);
router.post("/login", login);

router.use(protect);

router.get("/", (req, res) => {
  res.send("Authentication route!");
});

export default router;
