// Общий клиентский код: тема, меню, CSRF для htmx, таблицы, подтверждения, графики.
(function () {
  "use strict";

  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute("content") : "";
  }

  // CSRF-токен в каждом htmx-запросе
  document.addEventListener("htmx:configRequest", function (e) {
    e.detail.headers["X-CSRF-Token"] = csrf();
  });

  // --- Тема ---
  function toggleTheme() {
    var dark = document.documentElement.classList.toggle("dark");
    try { localStorage.setItem("ps-theme", dark ? "dark" : "light"); } catch (e) {}
    document.dispatchEvent(new CustomEvent("ps:theme"));
  }

  // --- Подтверждения и меню ---
  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-theme-toggle]");
    if (t) { toggleTheme(); return; }
    var m = e.target.closest("[data-menu-toggle]");
    if (m) {
      var sb = document.getElementById("sidebar");
      if (sb) sb.classList.toggle("hidden");
      return;
    }
    var c = e.target.closest("[data-confirm]");
    if (c && !window.confirm(c.getAttribute("data-confirm"))) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  }, true);

  document.addEventListener("submit", function (e) {
    var f = e.target;
    if (f.hasAttribute("data-confirm-submit") && !window.confirm(f.getAttribute("data-confirm-submit"))) {
      e.preventDefault();
    }
  }, true);

  // --- Таблицы: поиск, сортировка, фильтры ---
  function cellValue(row, idx) {
    var cell = row.cells[idx];
    if (!cell) return "";
    var v = cell.getAttribute("data-value");
    return v !== null ? v : cell.textContent.trim();
  }

  function compare(a, b) {
    var na = parseFloat(a), nb = parseFloat(b);
    if (!isNaN(na) && !isNaN(nb) && /^-?[\d.]+$/.test(a) && /^-?[\d.]+$/.test(b)) return na - nb;
    return a.localeCompare(b, "ru", { numeric: true, sensitivity: "base" });
  }

  function enhanceTable(table) {
    if (table.dataset.enhanced) return;
    table.dataset.enhanced = "1";
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var wrap = table.closest("[data-table-wrap]") || table.parentElement;
    var search = wrap.querySelector("[data-table-search]");
    var filters = wrap.querySelectorAll("[data-table-filter]");
    var counter = wrap.querySelector("[data-table-count]");

    function apply() {
      var q = search ? search.value.trim().toLowerCase() : "";
      var shown = 0;
      Array.prototype.forEach.call(tbody.rows, function (row) {
        if (row.hasAttribute("data-empty")) return;
        var ok = !q || row.textContent.toLowerCase().indexOf(q) !== -1;
        Array.prototype.forEach.call(filters, function (f) {
          if (!ok || !f.value) return;
          var attr = row.getAttribute("data-" + f.getAttribute("data-table-filter")) || "";
          if (attr.split(" ").indexOf(f.value) === -1) ok = false;
        });
        row.classList.toggle("hidden", !ok);
        if (ok) shown++;
      });
      if (counter) counter.textContent = shown;
    }
    if (search) search.addEventListener("input", apply);
    Array.prototype.forEach.call(filters, function (f) { f.addEventListener("change", apply); });

    var headers = table.tHead ? table.tHead.rows[0].cells : [];
    Array.prototype.forEach.call(headers, function (th, idx) {
      if (!th.hasAttribute("data-sort")) return;
      th.addEventListener("click", function () {
        var dir = th.getAttribute("data-sort-dir") === "asc" ? "desc" : "asc";
        Array.prototype.forEach.call(headers, function (h) { h.removeAttribute("data-sort-dir"); });
        th.setAttribute("data-sort-dir", dir);
        var rows = Array.prototype.filter.call(tbody.rows, function (r) { return !r.hasAttribute("data-empty"); });
        rows.sort(function (a, b) {
          var r = compare(cellValue(a, idx), cellValue(b, idx));
          return dir === "asc" ? r : -r;
        });
        rows.forEach(function (r) { tbody.appendChild(r); });
      });
    });
    apply();
  }

  // --- Графики ---
  var charts = [];
  function themeColors() {
    var dark = document.documentElement.classList.contains("dark");
    return { text: dark ? "#94a3b8" : "#64748b", grid: dark ? "rgba(148,163,184,0.12)" : "rgba(100,116,139,0.15)" };
  }

  function initCharts(root) {
    if (typeof Chart === "undefined") return;
    root.querySelectorAll("canvas[data-chart]").forEach(function (canvas) {
      if (canvas.dataset.ready) return;
      var src = document.getElementById(canvas.getAttribute("data-chart"));
      if (!src) return;
      canvas.dataset.ready = "1";
      var cfg = JSON.parse(src.textContent);
      var c = themeColors();
      Chart.defaults.color = c.text;
      Chart.defaults.font.family = "Inter, Segoe UI, Roboto, sans-serif";
      cfg.options = cfg.options || {};
      cfg.options.responsive = true;
      cfg.options.maintainAspectRatio = false;
      if (cfg.options.scales) {
        Object.keys(cfg.options.scales).forEach(function (k) {
          cfg.options.scales[k].grid = { color: c.grid };
        });
      }
      charts.push(new Chart(canvas, cfg));
    });
  }

  document.addEventListener("ps:theme", function () {
    var c = themeColors();
    charts.forEach(function (ch) {
      Chart.defaults.color = c.text;
      Object.keys(ch.options.scales || {}).forEach(function (k) {
        if (ch.options.scales[k].grid) ch.options.scales[k].grid.color = c.grid;
        if (ch.options.scales[k].ticks) ch.options.scales[k].ticks.color = c.text;
      });
      if (ch.options.plugins && ch.options.plugins.legend) ch.options.plugins.legend.labels.color = c.text;
      ch.update();
    });
  });

  // Подтверждение агрессивного профиля показывается только при его выборе
  function syncProfile() {
    var box = document.getElementById("aggressive-confirm");
    var sel = document.querySelector("input[data-profile-radio]:checked");
    if (box && sel) box.classList.toggle("hidden", sel.value !== "aggressive");
  }
  document.addEventListener("change", function (e) {
    if (e.target.matches && e.target.matches("input[data-profile-radio]")) syncProfile();
  });
  document.addEventListener("DOMContentLoaded", syncProfile);

  function init(root) {
    root.querySelectorAll("table[data-table]").forEach(enhanceTable);
    initCharts(root);
  }

  document.addEventListener("DOMContentLoaded", function () { init(document); });
  document.addEventListener("htmx:afterSettle", function (e) { init(e.target); });
})();
