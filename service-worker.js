const CACHE_NAME = "fraudexa-v2";

const FILES_TO_CACHE = [
  "./",
  "./index.html",
  "./manifest.json"
];

// Install
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(FILES_TO_CACHE);
    })
  );

  self.skipWaiting();
});

// Activate
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );

  self.clients.claim();
});

// Fetch
self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);

  if (
    request.method !== "GET" ||
    url.origin !== self.location.origin ||
    url.pathname.includes("/api/")
  ) {
    return;
  }

  event.respondWith(
    fetch(request).catch(async () => {
      if (request.mode === "navigate") {
        return await caches.match("./index.html");
      }

      return await caches.match(request);
    })
  );
});