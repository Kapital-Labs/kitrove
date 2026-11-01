const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const assert = require("node:assert/strict");
const output = process.env.SITE_TEST_OUTPUT;
if (!output)
  throw new Error("Set SITE_TEST_OUTPUT to an existing evidence directory.");
(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    permissions: ["clipboard-read", "clipboard-write"],
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  await page.goto("http://127.0.0.1:8731/");
  await page.screenshot({
    path: output + "/desktop.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.screenshot({ path: output + "/hero.png", animations: "disabled" });
  await page.getByRole("tab", { name: "Windows", exact: true }).click();
  assert(await page.locator("#windows").isVisible());
  assert(!(await page.locator("#macos").isVisible()));
  await page
    .getByRole("tab", { name: "Windows", exact: true })
    .press("ArrowRight");
  assert(await page.locator("#linux").isVisible());
  await page.getByRole("tab", { name: "Linux", exact: true }).press("Home");
  assert(await page.locator("#macos").isVisible());
  await page
    .getByText("Older Homebrew preview · RC4.2", { exact: true })
    .click();
  await page
    .getByRole("button", { name: "Copy Homebrew install command" })
    .click();
  assert.equal(
    await page.evaluate(() => navigator.clipboard.readText()),
    "brew install --cask kapital-labs/tap/kitrove-rc",
  );
  await page.evaluate(() =>
    Object.defineProperty(navigator.clipboard, "writeText", {
      value: () => Promise.reject(new Error("denied")),
    }),
  );
  await page.getByRole("button", { name: "Copy setup command" }).click();
  await page
    .getByRole("status")
    .filter({ hasText: "Could not access the clipboard" })
    .waitFor();
  await page.goto("http://127.0.0.1:8731/#linux");
  assert(await page.locator("#linux").isVisible());
  await page.goto("http://127.0.0.1:8731/docs/");
  await page.screenshot({ path: output + "/docs.png", fullPage: true });
  for (const width of [320, 390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const route of ["/", "/docs/"]) {
      await page.goto("http://127.0.0.1:8731" + route);
      assert(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        `overflow ${width} ${route}`,
      );
      if (width === 390)
        await page.screenshot({
          path: output + (route === "/" ? "/mobile.png" : "/docs-mobile.png"),
          fullPage: true,
          animations: "disabled",
        });
    }
  }
  const nojs = await browser.newContext({
    javaScriptEnabled: false,
    viewport: { width: 390, height: 844 },
  });
  const fallback = await nojs.newPage();
  await fallback.goto("http://127.0.0.1:8731/");
  for (const id of ["macos", "windows", "linux"])
    assert(await fallback.locator("#" + id).isVisible());
  assert.equal(errors.length, 0, errors.join("\n"));
  await browser.close();
  console.log(
    "PASS: desktop/mobile layouts, all platform tabs, keyboard, clipboard success/denial, deep link, docs, no-JS fallback, no browser errors.",
  );
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
