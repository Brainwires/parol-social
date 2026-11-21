// Runs before first paint (a classic, external script: the CSP allows no inline script).
// Applies the saved theme override so the page never flashes the other theme.
// "system" (or nothing saved) leaves the attribute off and the CSS follows the OS.
(function () {
  try {
    const theme = localStorage.getItem("parolnet.theme");
    if (theme === "light" || theme === "dark") {
      document.documentElement.setAttribute("data-theme", theme);
    }
  } catch (_) {
    // Storage is unavailable (private mode): follow the system.
  }
})();
