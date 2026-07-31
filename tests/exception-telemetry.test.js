import test from "node:test";
import assert from "node:assert/strict";
import {
  createExceptionReporter,
  installGlobalExceptionHandlers,
  normalizeErrorEvent,
  normalizeUnhandledRejection,
} from "../exception-telemetry.js";

test("normalizes a browser error with type, message, stack, and location", () => {
  const error = new TypeError("render failed");
  error.stack = "TypeError: render failed\n    at render (index.html:10:2)";

  assert.deepEqual(
    normalizeErrorEvent({
      error,
      message: error.message,
      filename: "index.html",
      lineno: 10,
      colno: 2,
    }),
    {
      source: "frontend.error",
      exceptionType: "TypeError",
      message: "render failed",
      stacktrace: error.stack,
      location: "index.html:10:2",
    },
  );
});

test("normalizes a non-Error unhandled rejection", () => {
  assert.deepEqual(normalizeUnhandledRejection({ reason: { code: 503 } }), {
    source: "frontend.unhandledrejection",
    exceptionType: "Object",
    message: '{"code":503}',
    stacktrace: "",
    location: "",
  });
});

test("bounds oversized exception fields", () => {
  const payload = normalizeUnhandledRejection({
    reason: {
      name: "HugeError",
      message: "m".repeat(20_000),
      stack: "s".repeat(70_000),
    },
  });

  assert.equal(payload.message.length, 16_384);
  assert.equal(payload.stacktrace.length, 65_536);
});

test("suppresses an identical exception inside the dedupe window", async () => {
  const sent = [];
  let now = 1_000;
  const report = createExceptionReporter((payload) => sent.push(payload), {
    now: () => now,
    dedupeWindowMs: 1_000,
  });
  const payload = normalizeUnhandledRejection({ reason: new Error("boom") });

  await report(payload);
  await report(payload);
  now = 2_001;
  await report(payload);

  assert.equal(sent.length, 2);
});

test("installs both global listeners and consumes sender rejection", async () => {
  const listeners = new Map();
  const target = {
    addEventListener(name, listener) {
      listeners.set(name, listener);
    },
  };
  const sent = [];
  let rejectNext = true;
  installGlobalExceptionHandlers(async (payload) => {
    sent.push(payload);
    if (rejectNext) {
      rejectNext = false;
      throw new Error("telemetry unavailable");
    }
  }, target);

  listeners.get("error")({ error: new Error("render failed") });
  listeners.get("unhandledrejection")({ reason: "promise failed" });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(sent.length, 2);
  assert.equal(sent[0].source, "frontend.error");
  assert.equal(sent[1].source, "frontend.unhandledrejection");
});
