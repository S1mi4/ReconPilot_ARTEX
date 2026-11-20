import type { Activity } from "./types";

type LoadStage = "sessions" | "history";

export type TaskSessionStreamState =
  | { status: "loading"; stage: LoadStage }
  | { status: "connecting" | "live" | "reconnecting" }
  | { status: "failed"; stage: LoadStage | "stream"; error?: string };

const RETRY_DELAYS = [500, 1500];
const LOAD_TIMEOUT = 15000;
const CONNECT_TIMEOUT = 12000;

export function startTaskSessionStream({
  loadSessions,
  loadHistory,
  openStream,
  onActivity,
  onState,
}: {
  loadSessions: (signal: AbortSignal) => Promise<void>;
  loadHistory: (signal: AbortSignal) => Promise<number>;
  openStream: (since: number) => EventSource;
  onActivity: (activity: Activity) => void;
  onState: (state: TaskSessionStreamState) => void;
}) {
  const lifetime = new AbortController();
  let stage: LoadStage | "stream" = "sessions";
  let stream: EventSource | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let cursor = 0;
  let attempts = 0;
  let failed = false;
  let wasLive = false;

  function clearTimer() {
    clearTimeout(timer);
    timer = undefined;
  }

  function closeStream() {
    const old = stream;
    stream = undefined;
    old?.close();
  }

  function retryLater(error?: unknown) {
    clearTimer();
    if (lifetime.signal.aborted) return;
    const delay = RETRY_DELAYS[attempts++];
    if (delay === undefined) {
      failed = true;
      onState({ status: "failed", stage, error: error instanceof Error ? error.message : undefined });
      return;
    }
    if (stage === "stream") onState({ status: wasLive ? "reconnecting" : "connecting" });
    timer = setTimeout(run, delay);
  }

  function streamWaiting() {
    onState({ status: wasLive ? "reconnecting" : "connecting" });
    // While CONNECTING the browser owns the retry and preserves Last-Event-ID.
    // Replace a stalled source only after closing it.
    timer ??= setTimeout(() => {
      closeStream();
      retryLater();
    }, CONNECT_TIMEOUT);
  }

  function connect() {
    clearTimer();
    try {
      const source = openStream(cursor);
      stream = source;
      source.onopen = () => {
        if (stream !== source) return;
        clearTimer();
        attempts = 0;
        wasLive = true;
        onState({ status: "live" });
      };
      source.onerror = () => {
        if (stream !== source) return;
        if (source.readyState === source.CLOSED) {
          closeStream();
          retryLater();
        } else {
          streamWaiting();
        }
      };
      source.onmessage = (event) => {
        if (stream !== source) return;
        let activity: Activity;
        try {
          activity = JSON.parse(event.data);
        } catch {
          return;
        }
        if (!Number.isSafeInteger(activity?.seq) || activity.seq <= cursor) return;
        onActivity(activity);
        cursor = activity.seq;
      };
      streamWaiting();
    } catch (error) {
      closeStream();
      retryLater(error);
    }
  }

  async function initialize() {
    while (stage !== "stream" && !lifetime.signal.aborted) {
      const signal = AbortSignal.any([lifetime.signal, AbortSignal.timeout(LOAD_TIMEOUT)]);
      onState({ status: "loading", stage });
      try {
        if (stage === "sessions") {
          await loadSessions(signal);
          signal.throwIfAborted();
          stage = "history";
        } else {
          const snapshot = await loadHistory(signal);
          signal.throwIfAborted();
          cursor = snapshot;
          stage = "stream";
        }
        attempts = 0;
      } catch (error) {
        retryLater(signal.reason ?? error);
        return;
      }
    }
    if (!lifetime.signal.aborted) connect();
  }

  function run() {
    clearTimer();
    if (stage === "stream") connect();
    else void initialize();
  }

  run();
  return {
    retry() {
      if (!failed || lifetime.signal.aborted) return;
      failed = false;
      attempts = 0;
      run();
    },
    close() {
      lifetime.abort();
      clearTimer();
      closeStream();
    },
  };
}
