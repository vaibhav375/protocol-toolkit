import { defineConfig, devices } from "@playwright/test";

// Starts the real app (Python backend + built UI) with a fixed session key and a
// throwaway data folder, then drives it in Chromium.
const PORT = 8799;
const python = process.env.PYTHON ?? "python3";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } }],
  webServer: {
    command: `cd .. && PT_TOKEN=e2e PT_DATA_DIR="$(mktemp -d)" ${python} -m protocol_toolkit --port ${PORT} --no-browser`,
    port: PORT,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
