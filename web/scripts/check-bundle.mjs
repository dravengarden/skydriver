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
        schema: "carrack.web-bundle-budget.v1",
        static_javascript_bytes: staticBytes,
        maximum_static_javascript_bytes: maximumStaticBytes,
        lazy_surfaces: lazySurfaces,
    }),
);
