/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#04121f",
        panel: "#0d2238",
        mint: "#4fd1c5",
        ember: "#f59e0b"
      },
      boxShadow: {
        glow: "0 20px 80px rgba(79, 209, 197, 0.18)"
      }
    }
  },
  plugins: []
};
