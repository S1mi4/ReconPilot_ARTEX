const assert = require("node:assert/strict");
const { setImmediate: flush } = require("node:timers/promises");
const { test } = require("node:test");
const { startTaskSessionStream } = require("./task-session-stream.ts");

function fixture(t, overrides = {}) {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const states = [];
  const sources = [];
  const events = [];
  const calls = { sessions: 0, history: 0 };
  const lifecycle = startTaskSessionStream({
    loadSessions(signal) {
      calls.sessions++;
      return overrides.sessions?.(signal) ?? Promise.resolve();
    },
    loadHistory(signal) {
      calls.history++;
      return overrides.history?.(signal) ?? Promise.resolve(10);
    },
    openStream(since) {
      const source = {
        since,
        CLOSED: 2,
        readyState: 0,
        close() {
          this.readyState = this.CLOSED;
        },
        open() {
          this.readyState = 1;
          this.onopen();
        },
        disconnect(readyState) {
          this.readyState = readyState;
          this.onerror();
        },
        message(seq) {
          this.onmessage({ data: JSON.stringify({ seq }) });
        },
      };
      sources.push(source);
      return source;
    },
    onActivity: (event) => events.push(event.seq),
    onState: (state) => states.push(state),
  });
  t.after(() => lifecycle.close());
  return { states, sources, events, calls, lifecycle };
}

test("retry after initial session list failure opens the stream from the history cursor", async (t) => {
  let failures = 3;
  const { calls, states, sources, lifecycle } = fixture(t, {
    sessions: async () => {
      if (failures-- > 0) throw new TypeError("Failed before the HTTP request");
    },
  });
  await flush();
  t.mock.timers.tick(500);
  await flush();
  t.mock.timers.tick(1500);
  await flush();
  assert.deepEqual(states.at(-1), { status: "failed", stage: "sessions", error: "Failed before the HTTP request" });
  assert.deepEqual(calls, { sessions: 3, history: 0 });
  assert.equal(sources.length, 0);

  lifecycle.retry();
  lifecycle.retry();
  await flush();
  assert.deepEqual(calls, { sessions: 4, history: 1 });
  assert.equal(sources[0].since, 10);
  assert.deepEqual(states.at(-1), { status: "connecting" });
  sources[0].open();
  assert.deepEqual(states.at(-1), { status: "live" });
});

test("history timeout retries the history step without reloading the session list", async (t) => {
  t.mock.method(AbortSignal, "timeout", (ms) => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(new DOMException("Request timed out", "TimeoutError")), ms);
    return controller.signal;
  });
  let first = true;
  const { calls, states, sources } = fixture(t, {
    history: (signal) => {
      if (!first) return Promise.resolve(22);
      first = false;
      return new Promise((_, reject) => signal.addEventListener("abort", () => reject(signal.reason), { once: true }));
    },
  });
  await flush();
  assert.deepEqual(states.at(-1), { status: "loading", stage: "history" });
  assert.equal(sources.length, 0);
  t.mock.timers.tick(15000);
  await flush();
  t.mock.timers.tick(500);
  await flush();
  assert.deepEqual(calls, { sessions: 1, history: 2 });
  assert.equal(sources[0].since, 22);
});

test("native reconnect keeps its source, and replacement resumes at the last applied event", async (t) => {
  const { calls, sources, states, events } = fixture(t);
  await flush();
  const first = sources[0];
  first.open();
  first.message(11);
  first.disconnect(0);
  assert.deepEqual(states.at(-1), { status: "reconnecting" });
  t.mock.timers.tick(5000);
  assert.equal(sources.length, 1);
  first.open();
  first.disconnect(first.CLOSED);
  assert.deepEqual(states.at(-1), { status: "reconnecting" });
  t.mock.timers.tick(500);
  assert.equal(sources[1].since, 11);
  sources[1].open();
  first.message(99);
  sources[1].message(11);
  sources[1].message(12);
  assert.deepEqual(events, [11, 12]);
  assert.deepEqual(states.at(-1), { status: "live" });
  assert.deepEqual(calls, { sessions: 1, history: 1 });
});

test("stalled sources are closed before replacement and eventually allow a manual retry", async (t) => {
  const { sources, states, lifecycle } = fixture(t);
  await flush();
  t.mock.timers.tick(12000);
  assert.equal(sources[0].readyState, sources[0].CLOSED);
  t.mock.timers.tick(500);
  sources[1].disconnect(sources[1].CLOSED);
  t.mock.timers.tick(1500);
  sources[2].disconnect(sources[2].CLOSED);
  assert.equal(states.at(-1).status, "failed");
  assert.equal(states.at(-1).stage, "stream");
  lifecycle.retry();
  assert.equal(sources.length, 4);
});

test("leaving the page aborts pending initialization and prevents a stale subscription", async (t) => {
  let complete;
  let signal;
  const { calls, sources, lifecycle } = fixture(t, {
    sessions: (requestSignal) => {
      signal = requestSignal;
      return new Promise((resolve) => {
        complete = resolve;
      });
    },
  });
  lifecycle.close();
  assert.equal(signal.aborted, true);
  complete();
  await flush();
  t.mock.timers.tick(30000);
  assert.deepEqual(calls, { sessions: 1, history: 0 });
  assert.equal(sources.length, 0);
});
