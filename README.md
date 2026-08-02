# Password Guardian

A password strength checker that runs entirely in your browser — nothing is sent to a server.

## Features
- Entropy-based strength scoring (1-10) with a transparent breakdown of the math
- Estimated time-to-crack, with an honest explanation of the assumptions behind it
- Two suggestion modes: leetspeak variants of your password, or random passphrases
- Guaranteed suggestion validity: every suggestion includes uppercase, lowercase, a number, a symbol, and is at least 8 characters
- Before → after score comparison when you apply a suggestion
- Undo / restore original / clear controls
- Copy-to-clipboard for both your password and suggestions

## Setup

Install dependencies:

```
npm install
```

Run the dev server:

```
npm run dev
```

This opens the app at `http://localhost:5173`.

## Build for production

```
npm run build
```

Output goes to the `dist/` folder — you can deploy that folder to any static host (Vercel, Netlify, GitHub Pages, etc).

## Project structure

```
password-guardian/
├── index.html          # HTML entry point
├── package.json        # Dependencies and scripts
├── vite.config.js       # Vite build configuration
├── tailwind.config.js   # Tailwind CSS configuration
├── postcss.config.js    # PostCSS configuration (required by Tailwind)
├── src/
│   ├── main.jsx          # React entry point, mounts App into #root
│   ├── App.jsx            # Main application component (all logic + UI)
│   └── index.css          # Tailwind directives
```
