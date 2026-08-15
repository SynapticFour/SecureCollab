import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const api = readFileSync(join(root, "lib/api.ts"), "utf8");
const visualizer = readFileSync(join(root, "components/ThresholdVisualizer.tsx"), "utf8");

if (!api.includes('headers["Authorization"]')) {
  console.error("api.ts must send Authorization Bearer tokens");
  process.exit(1);
}
if (api.includes("X-User-Email")) {
  console.error("api.ts must not send X-User-Email as identity");
  process.exit(1);
}
if (visualizer.includes("can decrypt results together")) {
  console.error("ThresholdVisualizer still claims crypto threshold decrypt");
  process.exit(1);
}
console.log("frontend contract checks passed");
