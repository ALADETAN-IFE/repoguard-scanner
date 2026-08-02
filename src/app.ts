import express from "express";
import router from "./routes";
import { errorHandler, observabilityMiddleware } from "@/middlewares";

const app = express();

// Enable trust proxy for reverse proxy
app.set("trust proxy", 1);

// Parse JSON request bodies
app.use(express.json());

app.use(observabilityMiddleware);

// Connect routes
app.use(router);

app.use(errorHandler);

export default app;
