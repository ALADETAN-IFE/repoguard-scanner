import app from "./app";
import { ENV } from "./config";
import { logger } from "@/utils";

const PORT = ENV.PORT || 3000;

const startServer = async () => {
  app.listen(PORT, () => {
    logger.info("Server", `Server is running on port ${PORT}`);
  });
};

startServer().catch((error) => {
  logger.error("Server", "Failed to start server", error as Error);
  process.exit(1);
});
