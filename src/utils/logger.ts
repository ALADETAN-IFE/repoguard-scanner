const logger = {
  info: (msg: string) => console.log(`[repoguard-scanner] ${msg}`),
  warn: (msg: string) => console.warn(`[repoguard-scanner] ${msg}`),
  error: (msg: string) => console.error(`[repoguard-scanner] ${msg}`),
};

export default logger;
