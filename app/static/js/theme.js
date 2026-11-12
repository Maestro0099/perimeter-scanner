// Загружается в <head> синхронно, чтобы избежать мигания темы.
// По умолчанию — тёмная тема; светлая включается переключателем и запоминается.
(function () {
  try {
    if (localStorage.getItem("ps-theme") !== "light") document.documentElement.classList.add("dark");
  } catch (e) { document.documentElement.classList.add("dark"); }
})();
