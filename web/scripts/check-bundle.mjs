import fs from "node:fs";
import path from "node:path";

const outputDirectory = path.resolve(import.meta.dirname, "../dist/client");
const assetsDirectory = path.join(outputDirectory, "assets");
const indexHtml = fs.readFileSync(path.join(outputDirectory, "index.html"), "utf8");
const staticAssets = [
    ...indexHtml.matchAll(/\b(?:src|href)="(\/assets\/[A-Za-z0-9._-]+\.js)"/g),
].map(([, asset]) => asset);
const uniqueStaticAssets = [...new Set(staticAssets)];
if (uniqueStaticAssets.length === 0) {
    throw new Error("built UI does not reference a JavaScript entry");
}

for (const requiredLink of [
    'rel="manifest" href="/manifest.webmanifest"',
    'rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png"',
]) {
    if (!indexHtml.includes(requiredLink)) {
        throw new Error(`built UI is missing PWA metadata: ${requiredLink}`);
    }
}

const manifest = JSON.parse(
    fs.readFileSync(path.join(outputDirectory, "manifest.webmanifest"), "utf8"),
);
if (
    manifest.name !== "Skydriver" ||
    manifest.start_url !== "/" ||
    manifest.scope !== "/" ||
    manifest.display !== "standalone"
) {
    throw new Error("PWA manifest does not define the canonical Skydriver application");
}
const requiredIcons = new Map([
    ["/pwa-192.png", "192x192"],
    ["/pwa-512.png", "512x512"],
    ["/pwa-maskable-512.png", "512x512"],
]);
for (const [source, sizes] of requiredIcons) {
    const icon = manifest.icons?.find((candidate) => candidate.src === source);
    if (icon?.sizes !== sizes || icon.type !== "image/png") {
        throw new Error(`PWA manifest is missing ${source} at ${sizes}`);
    }
    if (fs.statSync(path.join(outputDirectory, source)).size === 0) {
        throw new Error(`PWA icon is empty: ${source}`);
    }
}
if (
    !manifest.icons?.some(
        (icon) => icon.src === "/pwa-maskable-512.png" && icon.purpose === "maskable",
    )
) {
    throw new Error("PWA manifest is missing a maskable icon");
}
if (!fs.existsSync(path.join(outputDirectory, "service-worker.js"))) {
    throw new Error("built UI is missing its service worker");
}

const staticBytes = uniqueStaticAssets.reduce(
    (total, asset) => total + fs.statSync(path.join(outputDirectory, asset)).size,
    0,
);
const maximumStaticBytes = 512 * 1024;
if (staticBytes > maximumStaticBytes) {
    throw new Error(
        `initial JavaScript exceeds ${String(maximumStaticBytes)} bytes: ${String(staticBytes)}`,
    );
}

const chunks = fs.readdirSync(assetsDirectory);
const lazySurfaces = [
    "Dashboard",
    "FilesPage",
    "DriversPage",
    "AccessPage",
    "AnalyticsPage",
    "ActivityPage",
    "SettingsPage",
];
for (const surface of lazySurfaces) {
    if (!chunks.some((chunk) => chunk.startsWith(`${surface}-`) && chunk.endsWith(".js"))) {
        throw new Error(`${surface} must remain a lazy-loaded JavaScript chunk`);
    }
}

console.log(
    JSON.stringify({
        schema: "skydriver.web-bundle-budget.v1",
        static_javascript_bytes: staticBytes,
        maximum_static_javascript_bytes: maximumStaticBytes,
        lazy_surfaces: lazySurfaces,
    }),
);
