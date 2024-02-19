import express, { Express } from "express";
import cookieParser from "cookie-parser";
import compression from "compression";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

import authRouter from "./routes/auth.route";
import profileRouter from "./routes/profile.route";
import settingsRouter from "./routes/settings.route";

const app: Express = express();

app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:3001"],
    credentials: true,
  })
);

// Parse JSON bodies
app.use(express.json());
// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));
// Cookie parser middleware for parsing cookies sent by the client
app.use(cookieParser());
// Compress responses
app.use(compression());

// API routes go here
app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.use("/auth", authRouter);
// app.use("/profile", profileRouter);
app.use("/settings", settingsRouter);

export default app;
