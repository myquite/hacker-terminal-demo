// ============================================================================
// SCREENSAVER MODE
// ============================================================================
// Enabled by loading the page with ?screensaver. Hides the cursor and closes
// the window on any key press, click, or real mouse movement.

/**
 * Keep the canvas matched to the window (kiosk windows resize after mapping)
 */
function windowResized() {
  resizeCanvas(windowWidth, windowHeight);
}

(function () {
  if (!new URLSearchParams(location.search).has("screensaver")) return;

  const GRACE_MS = 1000;       // ignore input while the window is mapping
  const MOVE_THRESHOLD = 20;   // pixels of mouse travel before dismissing
  const startedAt = performance.now();
  let origin = null;

  document.documentElement.style.cursor = "none";
  document.body.style.cursor = "none";

  function dismiss() {
    if (performance.now() - startedAt < GRACE_MS) return;
    window.close();
  }

  window.addEventListener("keydown", dismiss);
  window.addEventListener("mousedown", dismiss);
  window.addEventListener("wheel", dismiss);
  window.addEventListener("touchstart", dismiss);
  window.addEventListener("mousemove", (event) => {
    if (!origin) {
      origin = { x: event.screenX, y: event.screenY };
      return;
    }
    const dx = event.screenX - origin.x;
    const dy = event.screenY - origin.y;
    if (dx * dx + dy * dy > MOVE_THRESHOLD * MOVE_THRESHOLD) dismiss();
  });
})();
