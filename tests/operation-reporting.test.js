import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");

test("execution records expose reporting for the selected trace", () => {
  assert.match(html, /data-action="report-operation-record"/);
  assert.match(html, /call\("report_operation_record", \{ traceId \}\)/);
  assert.match(html, /selectedOperationTraceId/);
});
