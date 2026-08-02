import { Request, Response } from "express";

export const rootHandler = (_req: Request, res: Response) => {
  res.json({
    name: "@repoguard/scanner",
    type: "monolith",
    version: "1.0.0",
    status: "running",
    endpoints: {
      root: "/",
      health: "/api/v1/health",
      docs: "/api-docs",
    },
  });
};
