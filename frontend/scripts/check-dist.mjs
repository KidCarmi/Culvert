// FE-1A generated-bundle security scan (FRONTEND-SECURITY-CONTRACT.md §3, §4;
// FE-1A directive §6–§7). Proves structural CSP-compatibility of the
// production output: no inline script/style, no inline event handlers, no
// external origins, no sourcemaps, a valid manifest whose referenced files
// exist. Exported as functions so the Vitest foundation tests exercise the
// same invariants CI enforces.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

export const distDir = fileURLToPath(new URL("../dist", import.meta.url));

export function listFiles(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...listFiles(p));
    else out.push(p);
  }
  return out.sort();
}

export function checkDist() {
  const errors = [];
  const files = listFiles(distDir).map((p) => relative(distDir, p));

  // 1. Shell structure: no inline script bodies, no inline styles, no
  //    on*= handlers, no external URLs. The shell must be static bytes.
  const html = readFileSync(join(distDir, "index.html"), "utf8");
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attrs = m[1] ?? "";
    const body = (m[2] ?? "").trim();
    if (body !== "") errors.push("index.html: inline <script> body present");
    if (!/\bsrc\s*=/.test(attrs))
      errors.push("index.html: <script> without src=");
  }
  if (/<style\b/i.test(html)) errors.push("index.html: inline <style> present");
  if (/\bstyle\s*=\s*["']/i.test(html))
    errors.push("index.html: style= attribute present");
  if (/\son[a-z]+\s*=\s*["']/i.test(html))
    errors.push("index.html: inline event handler attribute present");
  if (/__CSP_NONCE__|nonce=/.test(html))
    errors.push("index.html: nonce plumbing present (banned for the new app)");
  for (const m of html.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
    const url = m[1] ?? "";
    if (!url.startsWith("/") || url.startsWith("//"))
      errors.push(`index.html: non-same-origin resource URL ${url}`);
  }

  // 2. No sourcemaps: no emitted .map files, no sourceMappingURL directives.
  for (const f of files) {
    if (f.endsWith(".map")) errors.push(`sourcemap emitted: ${f}`);
    if (f.endsWith(".js") || f.endsWith(".css")) {
      if (readFileSync(join(distDir, f), "utf8").includes("sourceMappingURL="))
        errors.push(`sourceMappingURL directive in ${f}`);
    }
  }

  // 3. Manifest: present at dist/manifest.json (not .vite/), valid JSON,
  //    every referenced file exists in dist.
  if (!files.includes("manifest.json"))
    errors.push("manifest.json missing from dist root");
  if (files.some((f) => f.startsWith(".vite/")))
    errors.push("unexpected .vite/ output directory in dist");
  let manifest = {};
  try {
    manifest = JSON.parse(readFileSync(join(distDir, "manifest.json"), "utf8"));
  } catch (err) {
    errors.push(`manifest.json unreadable: ${String(err)}`);
  }
  const referenced = new Set();
  for (const [key, entry] of Object.entries(manifest)) {
    if (typeof entry.file !== "string") {
      errors.push(`manifest entry ${key} has no file field`);
      continue;
    }
    referenced.add(entry.file);
    for (const css of entry.css ?? []) referenced.add(css);
    for (const asset of entry.assets ?? []) referenced.add(asset);
  }
  for (const f of referenced) {
    if (!files.includes(f))
      errors.push(`manifest references missing file ${f}`);
  }

  // 4. Hashed assets live under assets/ with a content-hash suffix.
  for (const f of files) {
    if (f.startsWith("assets/") && !/-[A-Za-z0-9_-]{8,}\.[a-z0-9]+$/.test(f))
      errors.push(`asset without content hash: ${f}`);
  }

  return { errors, files };
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (invokedDirectly) {
  const { errors, files } = checkDist();
  if (errors.length > 0) {
    for (const e of errors) console.error(`check-dist: ${e}`);
    process.exit(1);
  }
  console.log(`check-dist: OK (${files.length} files)`);
}
