/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  // Классы, имя которых собирается в шаблонах динамически (sev-{{ уровень }} и т.п.)
  safelist: [
    { pattern: /^(sev|sev-dot|sev-border|bar|status)-(critical|high|medium|low|info|queued|running|done|failed|cancelled)$/ },
  ],
  content: ["../app/templates/**/*.html", "../app/static/js/app.js", "../app/**/*.py"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "Segoe UI", "Roboto", "Helvetica Neue", "Arial", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      colors: {
        // Единая схема уровней риска
        sev: {
          critical: "#b91c1c",
          high: "#ea580c",
          medium: "#ca8a04",
          low: "#2563eb",
          info: "#64748b",
        },
      },
    },
  },
  plugins: [require("@tailwindcss/forms")],
};
