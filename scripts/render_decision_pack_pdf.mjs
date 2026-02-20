import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      continue;
    }
    const key = token.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) {
      args[key] = "true";
      continue;
    }
    args[key] = value;
    i += 1;
  }
  return args;
}

function requirePath(pathValue, label) {
  if (!pathValue) {
    throw new Error(`${label} is required`);
  }
  const resolved = path.resolve(pathValue);
  if (!fs.existsSync(resolved)) {
    throw new Error(`${label} does not exist: ${resolved}`);
  }
  return resolved;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function loadPlaywright(scriptDir) {
  const candidates = [
    path.resolve(scriptDir, "..", "..", "epi-viewer", "node_modules", "playwright", "index.js"),
    path.resolve(scriptDir, "..", "..", "epi-viewer", "node_modules", "playwright", "index.mjs"),
  ];

  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) {
      continue;
    }
    const mod = await import(pathToFileURL(candidate).href);
    const playwright = mod.chromium ? mod : mod.default;
    if (playwright?.chromium) {
      return playwright;
    }
  }

  try {
    const mod = await import("playwright");
    const playwright = mod.chromium ? mod : mod.default;
    if (playwright?.chromium) {
      return playwright;
    }
  } catch (_err) {
    // handled below
  }

  throw new Error(
    "Unable to load Playwright. Expected module at epi-viewer/node_modules/playwright or in NODE_PATH.",
  );
}

function resolveChromiumExecutable() {
  const candidates = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

async function main() {
  const args = parseArgs(process.argv);
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));

  const htmlPath = requirePath(args.html, "--html");
  if (!args.pdf) {
    throw new Error("--pdf is required");
  }
  const pdfPath = path.resolve(args.pdf);

  const fontRegular = requirePath(
    args["font-regular"] ?? path.resolve(scriptDir, "fonts", "SourceSans3-Regular.otf"),
    "--font-regular",
  );
  const fontBold = requirePath(
    args["font-bold"] ?? path.resolve(scriptDir, "fonts", "SourceSans3-Bold.otf"),
    "--font-bold",
  );
  const fontItalic = requirePath(
    args["font-italic"] ?? path.resolve(scriptDir, "fonts", "SourceSans3-It.otf"),
    "--font-italic",
  );

  const library = args.library ?? "unknown-library";
  const client = args.client ?? "unknown-client";
  const engagement = args.engagement ?? "unknown-engagement";
  const packId = args["pack-id"] ?? "PACK-001";
  const headerLine = `Civitas Analytica | ${library} | ${client} | ${engagement} | ${packId}`;

  fs.mkdirSync(path.dirname(pdfPath), { recursive: true });
  const playwright = await loadPlaywright(scriptDir);
  const executablePath = resolveChromiumExecutable();
  const launchOptions = {
    headless: true,
    args: ["--disable-background-networking"],
  };
  if (executablePath) {
    launchOptions.executablePath = executablePath;
  }

  const browser = await playwright.chromium.launch(launchOptions);
  try {
    const context = await browser.newContext({ offline: true });
    const page = await context.newPage();

    await page.route("**/*", (route) => {
      const requestUrl = route.request().url();
      if (
        requestUrl.startsWith("file://") ||
        requestUrl.startsWith("data:") ||
        requestUrl.startsWith("about:")
      ) {
        route.continue();
      } else {
        route.abort();
      }
    });

    const regularFontUrl = pathToFileURL(fontRegular).href;
    const boldFontUrl = pathToFileURL(fontBold).href;
    const italicFontUrl = pathToFileURL(fontItalic).href;

    const printCss = `
@font-face {
  font-family: "EpiPrintSans";
  src: url("${regularFontUrl}") format("opentype");
  font-weight: 400;
  font-style: normal;
}
@font-face {
  font-family: "EpiPrintSans";
  src: url("${boldFontUrl}") format("opentype");
  font-weight: 700;
  font-style: normal;
}
@font-face {
  font-family: "EpiPrintSans";
  src: url("${italicFontUrl}") format("opentype");
  font-weight: 400;
  font-style: italic;
}
@page {
  size: A4;
  margin: 16mm 12mm 18mm 12mm;
}
html, body {
  font-family: "EpiPrintSans", "Segoe UI", sans-serif !important;
  -webkit-print-color-adjust: exact !important;
  print-color-adjust: exact !important;
}
a {
  color: inherit;
  text-decoration: none;
}
`;

    await page.goto(pathToFileURL(htmlPath).href, { waitUntil: "load" });
    await page.addStyleTag({ content: printCss });
    await page.emulateMedia({ media: "print" });
    await page.evaluate(async () => {
      if (document.fonts?.ready) {
        await document.fonts.ready;
      }
    });

    const headerTemplate = `
<style>
  .epi-header {
    width: 100%;
    padding: 0 10mm;
    font-size: 8px;
    color: #334155;
    font-family: "Segoe UI", sans-serif;
  }
</style>
<div class="epi-header">${escapeHtml(headerLine)}</div>
`;

    const footerTemplate = `
<style>
  .epi-footer {
    width: 100%;
    padding: 0 10mm;
    font-size: 8px;
    color: #475569;
    font-family: "Segoe UI", sans-serif;
    text-align: right;
  }
</style>
<div class="epi-footer">Page <span class="pageNumber"></span> / <span class="totalPages"></span></div>
`;

    await page.pdf({
      path: pdfPath,
      format: "A4",
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate,
      footerTemplate,
      margin: {
        top: "18mm",
        right: "12mm",
        bottom: "20mm",
        left: "12mm",
      },
      preferCSSPageSize: true,
    });

    await context.close();
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  process.stderr.write(`${err.message}\n`);
  process.exit(1);
});
