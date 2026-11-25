/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Graphite scale used for surfaces and borders.
        ink: {
          950: "#0b1014",
          900: "#11181e",
          850: "#161f26",
          800: "#1c2831",
          700: "#293640",
          600: "#41515e",
        },
        // Single restrained brand accent.
        accent: {
          DEFAULT: "#5ee5b5",
          hover: "#91f1cf",
          dim: "#153e32",
        },
        // Semantic severity (muted, not neon).
        sev: {
          critical: "#e5484d",
          high: "#ef7a35",
          medium: "#d5a021",
          low: "#3b9eff",
          info: "#6b7488",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }], // 11px
        xs: ["0.75rem", { lineHeight: "1.1rem" }], // 12px
        sm: ["0.875rem", { lineHeight: "1.4rem" }],
        base: ["1rem", { lineHeight: "1.6rem" }],
      },
      borderRadius: {
        DEFAULT: "8px",
        sm: "5px",
        md: "10px",
        lg: "12px",
      },
    },
  },
  plugins: [],
};
