import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";

const rootElement = document.getElementById("root");
if (rootElement === null) {
    throw new Error("Skydriver root element is missing");
}

const queryClient = new QueryClient();

createRoot(rootElement).render(
    <StrictMode>
        <QueryClientProvider client={queryClient}>
            <App />
        </QueryClientProvider>
    </StrictMode>,
);

if ("serviceWorker" in navigator) {
    globalThis.addEventListener("load", () => {
        void navigator.serviceWorker.register("/service-worker.js").catch(() => undefined);
    });
}
