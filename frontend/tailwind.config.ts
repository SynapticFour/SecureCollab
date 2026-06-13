// SPDX-License-Identifier: Apache-2.0
import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: "var(--sf-color-navy)",
        "primary-hover": "#162d52",
        accent: "var(--sf-color-teal)",
        "accent-hover": "#0284c7",
        success: "#10b981",
        warning: "#f59e0b",
      },
      fontFamily: {
        sans: ["var(--font-geist-sans)", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};
export default config;
