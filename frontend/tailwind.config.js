/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      minHeight: {
        // Full viewport minus the in-flow app footer (h-10 in Footer.tsx)
        page: 'calc(100vh - 2.5rem)',
      },
    },
  },
  plugins: [],
}
