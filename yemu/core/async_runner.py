import asyncio
import logging
import threading


class AsyncRunner:
    """
    Owns a single long-lived asyncio loop on a daemon thread.
    aiosqlite connections are bound to the loop that opened them, so every
    DB / orchestrator coroutine must be scheduled here rather than on
    throwaway per-thread loops.
    """

    def __init__(self, name="yemu-async"):
        self.logger = logging.getLogger(__name__)
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        self._thread.start()

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    @property
    def loop(self):
        return self._loop

    def submit(self, coro, on_done=None):
        """
        Schedule coro on the runner loop and return a concurrent.futures.Future.
        on_done(result, error) is called from the runner thread when it finishes;
        GTK callers must hop back to the main thread with GLib.idle_add.
        """
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        if on_done:

            def _done(fut):
                try:
                    on_done(fut.result(), None)
                except Exception as e:
                    self.logger.error(f"Background task failed: {e}")
                    on_done(None, e)

            future.add_done_callback(_done)
        return future

    def run(self, coro, timeout=None):
        """Block the calling thread until coro finishes on the runner loop."""
        if threading.current_thread() is self._thread:
            raise RuntimeError("AsyncRunner.run() called from the runner thread; await the coroutine instead")
        return self.submit(coro).result(timeout)

    def stop(self):
        if self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
