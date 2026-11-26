import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const dashboard = fs.readFileSync("phonecluster/dashboard.py", "utf8");
const names = ["formatJobOutput", "runParallelMap", "downloadLastMapJson", "workloadAction"];
const functions = names.map((name) => {
  const match = dashboard.match(new RegExp(`^(?:async )?function ${name}\\([^\\n]*\\n[\\s\\S]*?^}`, "m"));
  assert(match, name);
  return match[0];
});

const elements = {
  "map-mode": { value: "commands" },
  "map-target": { value: "auto" },
  "btn-run-map": {},
  "map-out": {},
  "map-summary-chips": {},
  "map-commands": { value: "echo first batch" },
  "btn-dl-map": { disabled: true },
  "distcc-cidr": { value: "" },
  "wl-action-out": { style: {} },
};
const toasts = [];
const downloads = [];
let rpc = {};
let postCount = 0;
let capturedBlob;
const context = vm.createContext({
  document: {
    getElementById: (id) => elements[id],
    createElement: () => ({ click: () => downloads.push(capturedBlob) }),
  },
  URL: { createObjectURL: (blob) => { capturedBlob = blob; return "blob:fixture"; } },
  Blob,
  authPost: async () => { postCount++; return rpc; },
  showToast: (message, kind) => toasts.push({ message, kind }),
  esc: (text) => text,
  refreshLive: () => {},
  loadWorkloads: () => {},
  setTimeout: () => {},
});
vm.runInContext("let lastMapData = null;\n" + functions.join("\n"), context);

rpc = {
  ok_count: 1, fail_count: 0, wall_sec: 0.01,
  results: [{ node_id: "phone", label: "first batch", duration_sec: 0.01, stdout: "result marker", ok: true }],
};
await vm.runInContext("runParallelMap()", context);
assert.equal(elements["btn-dl-map"].disabled, false);
elements["map-commands"].value = "";
rpc = { error: "provide non-empty commands list" };
await vm.runInContext("runParallelMap()", context);
assert.match(elements["map-out"].textContent, /Error/);
assert.equal(elements["btn-dl-map"].disabled, true);
vm.runInContext("downloadLastMapJson()", context);
assert.equal(downloads.length, 0);

let finishBatch;
const before = postCount;
rpc = new Promise(resolve => { finishBatch = resolve; });
const pendingBatch = vm.runInContext("runParallelMap()", context);
const repeatedBatch = vm.runInContext("runParallelMap()", context);
assert.equal(postCount - before, 1);
finishBatch({
  ok_count: 0, fail_count: 1, wall_sec: 1,
  results: [{ ok: false, outcome_unknown: true, stdout: "progress", stderr: "warning", error: "reply lost" }],
});
await Promise.all([pendingBatch, repeatedBatch]);
assert.match(elements["map-out"].textContent, /progress[\s\S]*warning[\s\S]*reply lost/);
assert.match(elements["map-summary-chips"].innerHTML, /Unknown: 1/);
assert.equal(elements["btn-run-map"].disabled, false);

rpc = { action: "llama-rpc-start", results: [{ node_id: "phone", ok: false, error: "fixture runtime missing" }] };
await vm.runInContext("workloadAction('llama-rpc-start')", context);
assert.equal(JSON.parse(elements["wl-action-out"].textContent).results[0].ok, false);
assert.equal(toasts.at(-1).kind, "bad");

rpc.results.push({ node_id: "second-phone", ok: true });
await vm.runInContext("workloadAction(\'llama-rpc-start\')", context);
assert.equal(toasts.at(-1).kind, "warn");
