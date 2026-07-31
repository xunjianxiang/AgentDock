const MESSAGE_LIMIT = 16_384;
const STACK_LIMIT = 65_536;

function bounded(value, limit) {
  return String(value ?? "").slice(0, limit);
}

function valueText(value) {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function exceptionType(value) {
  return value?.name || value?.constructor?.name || typeof value || "Unknown";
}

export function normalizeErrorEvent(event) {
  const error = event?.error;
  return {
    source: "frontend.error",
    exceptionType: bounded(exceptionType(error), 256),
    message: bounded(error?.message || event?.message || "Unknown frontend error", MESSAGE_LIMIT),
    stacktrace: bounded(error?.stack, STACK_LIMIT),
    location: bounded(
      event?.filename ? `${event.filename}:${event.lineno || 0}:${event.colno || 0}` : "",
      2_048,
    ),
  };
}

export function normalizeUnhandledRejection(event) {
  const reason = event?.reason;
  return {
    source: "frontend.unhandledrejection",
    exceptionType: bounded(exceptionType(reason), 256),
    message: bounded(reason?.message || valueText(reason) || "Unhandled promise rejection", MESSAGE_LIMIT),
    stacktrace: bounded(reason?.stack, STACK_LIMIT),
    location: "",
  };
}

function fingerprint(payload) {
  return [payload.source, payload.exceptionType, payload.message, payload.stacktrace].join("\u0000");
}

export function createExceptionReporter(send, options = {}) {
  const now = options.now || Date.now;
  const dedupeWindowMs = options.dedupeWindowMs || 1_000;
  const recent = new Map();

  return async (payload) => {
    const time = now();
    const key = fingerprint(payload);
    if (time - (recent.get(key) ?? -Infinity) <= dedupeWindowMs) return false;

    recent.set(key, time);
    for (const [candidate, seenAt] of recent) {
      if (time - seenAt > dedupeWindowMs || recent.size > 64) recent.delete(candidate);
    }
    await send(payload);
    return true;
  };
}

export function installGlobalExceptionHandlers(send, target = window) {
  const report = createExceptionReporter(async (payload) => {
    try {
      await send(payload);
    } catch {
      // Telemetry failures must not create recursive unhandled rejections.
    }
  });

  target.addEventListener("error", (event) => {
    void report(normalizeErrorEvent(event));
  });
  target.addEventListener("unhandledrejection", (event) => {
    void report(normalizeUnhandledRejection(event));
  });
}
