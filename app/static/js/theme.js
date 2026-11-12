// Загружается в <head> синхронно, чтобы избежать мигания темы.
(function () {
  try {
    var t = localStorage.getItem("ps-theme");
    if (t === "dark" || (!t && window.matchMedia("(prefers-color-scheme: dark)").matches)) {
      document.documentElement.classList.add("dark");
    }
  } catch (e) { /* localStorage недоступен */ }
})();
