import { launchRole } from "./runtime-launcher.mjs";

launchRole("mcp", process.argv.slice(2), import.meta.url);
