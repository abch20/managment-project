import cookies from "cookie-parser";
import cors from "cors";
import express from "express";
import authRouter from "./routes/auth.routes.js";
import healthCheckRouter from "./routes/healthcheck.routes.js";
const app = express();

//basic configuration
app.use(express.json({ limit: "16kB" }));
app.use(express.urlencoded({ extended: true, limit: "16kB" }));
app.use(express.static("public"));
app.use(cookies());

//cors configurations
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:3000",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/auth", authRouter);

app.get("/", (req, res) => {
  res.send("Hello world");
});

export default app;
