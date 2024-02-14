import express, { Express } from "express";
import cookieParser from "cookie-parser";
import compression from "compression";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

import authRouter from "./routes/auth.route";
import movieRouter from "./routes/movie.route";

const app: Express = express();

app.use(
  cors({
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

app.use("/", movieRouter);

export default app;
