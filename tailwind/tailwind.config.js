/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
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
          medium: "#d97706",
          low: "#2563eb",
          info: "#64748b",
        },
      },
    },
  },
  plugins: [require("@tailwindcss/forms")],
};
