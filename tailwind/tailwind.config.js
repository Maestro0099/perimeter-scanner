/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  // Классы, имя которых собирается в шаблонах динамически (sev-{{ уровень }} и т.п.)
  safelist: [
    { pattern: /^(sev|sev-dot|sev-border|sev-text|bar|status|log)-(critical|high|medium|low|info|queued|running|done|failed|cancelled)$/ },
  ],
  content: ["../app/templates/**/*.html", "../app/static/js/app.js", "../app/**/*.py"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Golos Text", "Segoe UI", "Roboto", "Helvetica Neue", "Arial", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      colors: {
        // Акцент интерфейса — «терминальный» циан
        accent: {
          50: "#ecfeff", 100: "#cffafe", 200: "#a5f3fc", 300: "#67e8f9", 400: "#22d3ee",
          500: "#06b6d4", 600: "#0891b2", 700: "#0e7490", 800: "#155e75", 900: "#164e63",
        },
        // Тёмные поверхности: глубокий сине-чёрный
        slate: { 700: "#22314e", 800: "#141f35", 900: "#0a111f", 950: "#050810" },
        // Единая схема уровней риска
        sev: { critical: "#e11d48", high: "#f97316", medium: "#eab308", low: "#38bdf8", info: "#64748b" },
      },
      keyframes: {
        sweep: { to: { transform: "rotate(360deg)" } },
        stripes: { to: { backgroundPosition: "32px 0" } },
        blink: { "50%": { opacity: "0.25" } },
      },
      animation: {
        sweep: "sweep 4s linear infinite",
        stripes: "stripes 1s linear infinite",
        blink: "blink 1.6s ease-in-out infinite",
      },
    },
  },
  plugins: [require("@tailwindcss/forms")],
};
