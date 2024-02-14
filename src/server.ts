import http from "http";

import app from "./app";
import mongoose from "mongoose";

const MONGODB_URI = process.env.MONGODB_URI as string;
const PORT = process.env.PORT || 8000;

const server = http.createServer(app);
server.listen(PORT, () => {
  console.log("Server is running on port", PORT);
});

mongoose.Promise = Promise;
mongoose.connect(MONGODB_URI);
mongoose.connection.on("error", (error: Error) => console.log(error));

process.on("unhandledRejection", (err: Error) => {
  console.log("UNHANDLED REJECTION --> SHUTTING DOWN!!");
  console.log(err.name, err.message);

  server.close(() => {
    process.exit(1);
  });
});

process.on("uncaughtException", (err: Error) => {
  console.log("UNHANDLED EXCEPTION --> SHUTTING DOWN!!");
  console.log(err.name, err.message);
  process.exit(1);
});
