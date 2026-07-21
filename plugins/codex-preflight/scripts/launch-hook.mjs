import { launchRole } from "./runtime-launcher.mjs";

launchRole("hook", process.argv.slice(2), import.meta.url);
