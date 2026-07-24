const CACHE_NAME = "skydriver-shell-v1";
const SHELL_RESOURCES = [
    "/",
    "/manifest.webmanifest",
    "/favicon-32.png",
    "/favicon-48.png",
    "/apple-touch-icon.png",
    "/pwa-192.png",
    "/pwa-512.png",
    "/pwa-maskable-512.png",
    "/skydriver-mark.png",
];

self.addEventListener("install", (event) => {
    event.waitUntil(
        caches
            .open(CACHE_NAME)
            .then((cache) => cache.addAll(SHELL_RESOURCES))
            .then(() => self.skipWaiting()),
    );
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches
            .keys()
            .then((names) =>
                Promise.all(
                    names.filter((name) => name !== CACHE_NAME).map((name) => caches.delete(name)),
                ),
            )
            .then(() => self.clients.claim()),
    );
});

self.addEventListener("fetch", (event) => {
    const request = event.request;
    const url = new URL(request.url);
    if (
        request.method !== "GET" ||
        url.origin !== self.location.origin ||
        url.pathname.startsWith("/api/")
    ) {
        return;
    }

    if (request.mode === "navigate") {
        event.respondWith(
            fetch(request).catch(async () => {
                const cached = await caches.match("/");
                return cached ?? Response.error();
            }),
        );
        return;
    }

    if (url.pathname.startsWith("/assets/") || SHELL_RESOURCES.includes(url.pathname)) {
        event.respondWith(
            caches.match(request).then(async (cached) => {
                if (cached !== undefined) return cached;
                const response = await fetch(request);
                if (response.ok) {
                    const cache = await caches.open(CACHE_NAME);
                    await cache.put(request, response.clone());
                }
                return response;
            }),
        );
    }
});
