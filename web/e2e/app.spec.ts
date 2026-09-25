import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";

const TOKEN = "e2e";
const DNS_PORT = "10399";
const SMTP_PORT = "2599";

async function open(page: Page) {
  await page.goto(`/?t=${TOKEN}`);  // the launch link: sets the session cookie, then redirects
  await expect(page.getByRole("navigation", { name: "Tools" })).toBeVisible();
}

async function go(page: Page, name: string) {
  await page.getByRole("navigation", { name: "Tools" }).getByRole("button", { name }).click();
}

async function startTestServer(page: Page, kind: "SMTP" | "DNS", port: string) {
  await go(page, "Test servers");
  const card = page.locator("section").filter({ has: page.getByRole("heading", { name: `${kind} server` }) });
  const button = card.getByRole("button", { name: /^(Start|Stop)$/ });
  if ((await button.textContent())?.includes("Start")) {
    await card.getByLabel(`${kind} port`).fill(port);
    await button.click();
  }
  await expect(card.getByRole("button", { name: "Stop" })).toBeVisible();
}

test.beforeEach(async ({ page }) => { await open(page); });

test("the API refuses requests without the session key", async ({ playwright }) => {
  const anonymous = await playwright.request.newContext({ baseURL: "http://127.0.0.1:8799" });
  expect((await anonymous.get("/api/info")).status()).toBe(401);
  expect((await anonymous.get("/api/info", { headers: { Origin: "https://evil.example" } })).status()).toBe(403);
  await anonymous.dispose();
});

test("every screen renders", async ({ page }) => {
  for (const [nav, heading] of [["HTTP", "HTTP"], ["DNS", "DNS"], ["SMTP", "SMTP"], ["Mail check", "Mail check"],
    ["Scanner", "Scanner"], ["Test servers", "Test servers"], ["Assistant", "Assistant"], ["Inspector", "Inspector"]]) {
    await go(page, nav);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  }
});

test("DNS query against the built-in DNS server", async ({ page }) => {
  await startTestServer(page, "DNS", DNS_PORT);
  await go(page, "DNS");
  await page.getByLabel("Name").fill("toolkit.test");
  await page.getByLabel("Record type").selectOption("MX");
  await page.locator("input[list=resolvers]").fill(`127.0.0.1:${DNS_PORT}`);
  await page.getByRole("button", { name: "Query" }).click();
  await expect(page.getByText("NOERROR", { exact: true })).toBeVisible();
  await expect(page.getByText("10 mail.toolkit.test.")).toBeVisible();
  // the exchange streams into the Wire column
  await expect(page.locator("aside").getByText(/DNS MX toolkit\.test/)).toBeVisible();
});

test("an email sent over SMTP lands in the built-in inbox", async ({ page }) => {
  const subject = `E2E ${Date.now()}`;
  await startTestServer(page, "SMTP", SMTP_PORT);
  await go(page, "SMTP");
  await page.getByLabel("Server").fill("127.0.0.1");
  await page.getByLabel("Port").fill(SMTP_PORT);
  await page.getByRole("radio", { name: "Plain" }).click();
  await page.getByLabel("Subject").fill(subject);
  await page.getByRole("button", { name: "Send email" }).click();
  await expect(page.getByText("Accepted by the server")).toBeVisible();
  // the conversation shows the command (the Wire column shows it too, so look in the main area)
  await expect(page.getByRole("main").getByText("MAIL FROM:<you@example.com>", { exact: false })).toBeVisible();
  await go(page, "Test servers");
  await page.getByRole("button", { name: new RegExp(subject) }).click();
  await expect(page.getByText("This message was sent by a hand-written SMTP client.")).toBeVisible();
});

test("HTTP request, inspector byte highlighting and exports", async ({ page }) => {
  await go(page, "HTTP");
  await page.getByRole("radio", { name: "HTTP/1.1" }).click();
  // Ask the toolkit's own server for a protected URL: a deterministic 401 with no internet needed
  await page.getByLabel("URL").fill("http://127.0.0.1:8799/api/info");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(page.getByText("401", { exact: true })).toBeVisible();
  await expect(page.getByText("TCP connect")).toBeVisible();

  await page.getByRole("button", { name: "Inspect wire" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Inspector" })).toBeVisible();
  await page.getByText("GET /api/info", { exact: true }).first().click();
  await page.getByRole("button", { name: /^Start line/ }).hover();
  await expect(page.locator("span[style*='background']").first()).toBeVisible();  // highlighted bytes

  await page.getByRole("button", { name: "Export" }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("menu").getByText("Packet capture (.pcapng)").click();
  const file = await (await download).path();
  const bytes = readFileSync(file);
  expect(bytes.subarray(0, 4).toString("hex")).toBe("0a0d0d0a");  // pcapng section header

  await page.getByRole("button", { name: "Export" }).click();
  const harDownload = page.waitForEvent("download");
  await page.getByRole("menu").getByText("HAR (.har)").click();
  const har = JSON.parse(readFileSync(await (await harDownload).path(), "utf8"));
  expect(har.log.entries[0].response.status).toBe(401);
});

test("the theme choice survives a reload", async ({ page }) => {
  const html = page.locator("html");
  const before = await html.getAttribute("data-theme");
  await page.getByRole("button", { name: /Switch to (light|dark) theme/ }).click();
  const after = await html.getAttribute("data-theme");
  expect(after).not.toBe(before);
  await page.reload();
  await expect(html).toHaveAttribute("data-theme", after!);
});

test("the assistant explains how to get a model running", async ({ page }) => {
  await go(page, "Assistant");
  await expect(page.getByText(/Ollama .* free, stays on this Mac|Ollama isn't running|Install Ollama/)).toBeVisible();
  await page.getByRole("radio", { name: "Claude" }).click();
  await expect(page.getByText(/Anthropic SDK|Key set|ANTHROPIC_API_KEY/)).toBeVisible();
});
