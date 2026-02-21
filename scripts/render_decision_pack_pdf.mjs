import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const BRAND_MARKER = "civitas-mark-v1";
const PACK_META_FILENAME = "epi.decision_pack.v1.json";

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

function requireNonEmptyString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} is required and must be a non-empty string`);
  }
  return value.trim();
}

function resolveAncestorFile(startPath, fileName) {
  let current = path.dirname(startPath);
  while (true) {
    const candidate = path.join(current, fileName);
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

function loadPackIdentity(htmlPath) {
  const metaPath = resolveAncestorFile(htmlPath, PACK_META_FILENAME);
  if (!metaPath) {
    throw new Error(
      `${PACK_META_FILENAME} not found. Expected it in an ancestor directory of: ${htmlPath}`,
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(metaPath, "utf8"));
  } catch (err) {
    throw new Error(`Failed to parse ${metaPath}: ${err.message}`);
  }

  if (!parsed?.pack_meta || typeof parsed.pack_meta !== "object") {
    throw new Error(`${metaPath} is missing pack_meta`);
  }

  return {
    metaPath,
    packType: requireNonEmptyString(parsed.pack_meta.pack_type, `${metaPath} pack_meta.pack_type`),
    library: requireNonEmptyString(parsed.pack_meta.library, `${metaPath} pack_meta.library`),
    client: requireNonEmptyString(parsed.pack_meta.client, `${metaPath} pack_meta.client`),
    engagement: requireNonEmptyString(parsed.pack_meta.engagement, `${metaPath} pack_meta.engagement`),
  };
}

function loadCivitasMarkSvg(scriptDir) {
  const svgPath = requirePath(path.resolve(scriptDir, "assets", "civitas-mark.svg"), "civitas mark svg");
  const svg = fs.readFileSync(svgPath, "utf8").trim();
  if (!svg.includes(BRAND_MARKER)) {
    throw new Error(`${svgPath} must include marker id '${BRAND_MARKER}'`);
  }
  return svg;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildPdfHeaderMarkSvg(markSvg) {
  const toneMap = [
    ["#0B1120", "#0B1220"],
    ["#1E293B", "#1F2937"],
    ["#020617", "#0A0F1B"],
    ["#0F172A", "#111827"],
    ["#334155", "#344255"],
    ["#F8FAFC", "#D9E2EC"],
    ["#94A3B8", "#8E9BAE"],
    ["#CBD5E1", "#BBC7D6"],
    ["#2563EB", "#66758E"],
    ["#60A5FA", "#8A98AE"],
  ];

  let toned = markSvg;
  for (const [source, target] of toneMap) {
    toned = toned.replace(new RegExp(escapeRegex(source), "gi"), target);
  }
  toned = toned.replace(/aria-label="[^"]*"/i, 'aria-hidden="true"');
  if (!/shape-rendering=/i.test(toned)) {
    toned = toned.replace(
      /<svg\b/i,
      '<svg shape-rendering="geometricPrecision" text-rendering="geometricPrecision"',
    );
  }
  return toned;
}

function ensureHtmlBranding(htmlPath, packIdentity, markSvg) {
  let html = fs.readFileSync(htmlPath, "utf8");
  let updated = false;

  const identity = `${packIdentity.packType} / ${packIdentity.library} / ${packIdentity.client} / ${packIdentity.engagement}`;
  const printTheme = `
<style id="civitas-print-theme">
  :root {
    color-scheme: light;
  }
  html, body {
    background: #f7f7f4 !important;
    color: #0b1220 !important;
  }
  body {
    line-height: 1.45;
  }
  h1, h2, h3, h4 {
    color: #0b1220;
    letter-spacing: 0.01em;
    margin-block: 0.45em 0.35em;
  }
  p, li, dd, dt {
    color: #1f2937;
  }
  code, pre, kbd {
    font-family: "Consolas", "Courier New", monospace;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    border: 1px solid #cfd7e2;
    background: #fbfcf8;
    font-size: 12px;
  }
  table thead th {
    background: #e6ebf3;
    color: #0b1220;
    border-bottom: 1px solid #c1ccd9;
    font-size: 10px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    font-weight: 700;
    padding: 6px 8px;
  }
  table tbody td {
    border-top: 1px solid #dde4ee;
    color: #0f172a;
    padding: 6px 8px;
  }
  table tbody tr:nth-child(even) td {
    background: #f0f4fa;
  }
  table td:first-child,
  table th:first-child,
  table td:first-child code {
    font-family: "Consolas", "Courier New", monospace;
    letter-spacing: 0.02em;
  }
  table th:nth-last-child(-n+2),
  table td:nth-last-child(-n+2),
  table th.num,
  table td.num,
  table th[data-align="right"],
  table td[data-align="right"] {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .status-gap,
  .status--gap,
  .gap-pill,
  [data-status-badge="gap"] {
    display: inline-flex;
    align-items: center;
    border-radius: 9999px;
    border: 1px solid #d08aa1;
    background: #fde6ed;
    color: #8a2046;
    padding: 1px 8px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    line-height: 1.2;
  }
  td[data-status="gap"],
  td.status-gap,
  td.status--gap {
    background: #fde6ed !important;
    color: #8a2046;
    text-align: center;
    font-weight: 700;
  }
</style>
`;
  const banner = `
<!-- civitas-branding:${BRAND_MARKER} -->
<style id="civitas-branding-style">
  [data-civitas-brand="${BRAND_MARKER}"] {
    position: sticky;
    top: 0;
    z-index: 2147483000;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 10px 14px;
    border-bottom: 1px solid #cbd5e1;
    background: #f8fafc;
    color: #0f172a;
    font-family: "EpiPrintSans", "Segoe UI", sans-serif;
    font-size: 12px;
    line-height: 1.25;
  }
  [data-civitas-brand="${BRAND_MARKER}"] .civitas-brand-left {
    display: inline-flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
  }
  [data-civitas-brand="${BRAND_MARKER}"] .civitas-brand-primary {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-weight: 700;
    letter-spacing: 0.02em;
    text-transform: uppercase;
  }
  [data-civitas-brand="${BRAND_MARKER}"] .civitas-brand-subline {
    margin-left: 26px;
    font-size: 10px;
    letter-spacing: 0.06em;
    color: #475569;
    font-weight: 400;
    text-transform: none;
  }
  [data-civitas-brand="${BRAND_MARKER}"] .civitas-brand-mark {
    width: 18px;
    height: 18px;
    color: #0f172a;
    flex: 0 0 auto;
  }
  [data-civitas-brand="${BRAND_MARKER}"] .civitas-brand-right {
    font-size: 11px;
    color: #334155;
    white-space: nowrap;
  }
  @media print {
    [data-civitas-brand="${BRAND_MARKER}"] {
      display: none !important;
    }
  }
</style>
<div data-civitas-brand="${BRAND_MARKER}">
  <div class="civitas-brand-left">
    <div class="civitas-brand-primary">
      <span class="civitas-brand-mark">${markSvg}</span>
      <span>Civitas EPI Rail</span>
    </div>
    <div class="civitas-brand-subline">Civitas Analytica — Engineered truth</div>
  </div>
  <div class="civitas-brand-right">${escapeHtml(identity)}</div>
</div>
`;

  if (!html.includes('id="civitas-print-theme"')) {
    const headOpenMatch = html.match(/<head\b[^>]*>/i);
    if (headOpenMatch) {
      const headOpenTag = headOpenMatch[0];
      html = html.replace(headOpenTag, `${headOpenTag}\n${printTheme}`);
    } else {
      const bodyOpenMatch = html.match(/<body\b[^>]*>/i);
      if (bodyOpenMatch) {
        const bodyOpenTag = bodyOpenMatch[0];
        html = html.replace(bodyOpenTag, `${bodyOpenTag}\n${printTheme}`);
      } else {
        html = `${printTheme}\n${html}`;
      }
    }
    updated = true;
  }

  if (!html.includes(`data-civitas-brand="${BRAND_MARKER}"`)) {
    const bodyOpenMatch = html.match(/<body\b[^>]*>/i);
    if (bodyOpenMatch) {
      const bodyOpenTag = bodyOpenMatch[0];
      html = html.replace(bodyOpenTag, `${bodyOpenTag}\n${banner}`);
    } else {
      html = `${banner}\n${html}`;
    }
    updated = true;
  }

  if (updated) {
    fs.writeFileSync(htmlPath, html, "utf8");
  }
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
    args["font-regular"] ??
      path.resolve(scriptDir, "fonts", "ibm-plex", "Sans", "IBMPlexSans-Regular.ttf"),
    "--font-regular",
  );
  const fontBold = requirePath(
    args["font-bold"] ??
      path.resolve(scriptDir, "fonts", "ibm-plex", "Sans", "IBMPlexSans-Bold.ttf"),
    "--font-bold",
  );
  const fontItalic = requirePath(
    args["font-italic"] ??
      path.resolve(scriptDir, "fonts", "ibm-plex", "Sans", "IBMPlexSans-Italic.ttf"),
    "--font-italic",
  );
  const packIdentity = loadPackIdentity(htmlPath);
  const markSvg = loadCivitasMarkSvg(scriptDir);
  const pdfHeaderMarkSvg = buildPdfHeaderMarkSvg(markSvg);
  ensureHtmlBranding(htmlPath, packIdentity, markSvg);

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
  margin: 22mm 12mm 18mm 12mm;
}
html, body {
  font-family: "EpiPrintSans", "Segoe UI", sans-serif !important;
  background: #f7f7f4 !important;
  color: #0b1220 !important;
  line-height: 1.46;
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
  .epi-header {
    width: 100%;
    box-sizing: border-box;
    padding: 0 10mm;
    font-size: 8px;
    color: #0b1220;
    font-family: "EpiPrintSans", "Segoe UI", sans-serif;
  }
  .epi-header-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border: 0.5px solid #c5d0dd;
    border-bottom-color: #b9c5d4;
    border-radius: 2mm;
    background: rgba(11, 18, 32, 0.07);
    padding: 1.6mm 2.3mm 1.4mm;
  }
  .epi-header-left {
    display: inline-flex;
    align-items: center;
    gap: 2.2mm;
    color: #0f172a;
    font-size: 8px;
    text-transform: uppercase;
  }
  .epi-header-brand {
    display: inline-flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.2mm;
  }
  .epi-header-title {
    font-size: 8px;
    font-weight: 700;
    letter-spacing: 0.03em;
    color: #0f172a;
    text-transform: uppercase;
  }
  .epi-header-subline {
    font-size: 10px;
    font-weight: 400;
    letter-spacing: 0.05em;
    color: #475569;
    text-transform: none;
    line-height: 1.1;
  }
  .epi-mark {
    width: 4.8mm;
    height: 4.8mm;
    flex: 0 0 auto;
    line-height: 0;
    margin-bottom: -0.2mm;
  }
  .epi-mark svg {
    width: 100%;
    height: 100%;
    display: block;
  }
  .epi-header-right {
    text-align: right;
    font-size: 7px;
    line-height: 1.3;
    color: #0b1220;
  }
  .epi-label {
    color: #0f172a;
    font-weight: 700;
  }
</style>
<div class="epi-header">
  <div class="epi-header-row">
    <div class="epi-header-left">
      <span class="epi-mark">${pdfHeaderMarkSvg}</span>
      <span class="epi-header-brand">
        <span class="epi-header-title">Civitas EPI Rail</span>
        <span class="epi-header-subline">Civitas Analytica — Engineered truth</span>
      </span>
    </div>
    <div class="epi-header-right">
      <div><span class="epi-label">pack_type</span>: ${escapeHtml(packIdentity.packType)}</div>
      <div><span class="epi-label">library</span>: ${escapeHtml(packIdentity.library)}</div>
      <div><span class="epi-label">client</span>: ${escapeHtml(packIdentity.client)}</div>
      <div><span class="epi-label">engagement</span>: ${escapeHtml(packIdentity.engagement)}</div>
    </div>
  </div>
</div>
`;

    const footerTemplate = `
<style>
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
  .epi-footer {
    width: 100%;
    box-sizing: border-box;
    padding: 0 10mm;
    font-size: 8px;
    color: #475569;
    font-family: "EpiPrintSans", "Segoe UI", sans-serif;
  }
  .epi-footer-row {
    border-top: 0.5px solid #cbd5e1;
    padding-top: 1.2mm;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .epi-integrity {
    color: #334155;
    font-size: 7px;
    font-weight: 700;
    letter-spacing: 0.01em;
  }
  .epi-pagination {
    text-align: right;
    color: #0f172a;
    font-size: 8px;
  }
</style>
<div class="epi-footer">
  <div class="epi-footer-row">
    <div class="epi-integrity">Sealed + Verifiable</div>
    <div class="epi-pagination">Page <span class="pageNumber"></span> / <span class="totalPages"></span></div>
  </div>
</div>
`;

    await page.pdf({
      path: pdfPath,
      format: "A4",
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate,
      footerTemplate,
      margin: {
        top: "22mm",
        right: "12mm",
        bottom: "18mm",
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
