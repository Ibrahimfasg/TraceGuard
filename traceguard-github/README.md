# TraceGuard

TraceGuard checks JavaScript and TypeScript code for common security problems. It runs in your browser. It does not upload or save your source code.

This is an educational project. A clean result does not prove that a program is secure.

## Use it

1. Paste code or choose a local `.js`, `.jsx`, `.ts`, or `.tsx` file.
2. Select **Run audit**.
3. Open a finding to see its location, why it matters, and how to fix it.
4. Export the results as JSON if you want to save a report.

Select **Load example** to try the scanner on an intentionally unsafe sample.

## Checks

TraceGuard currently has 11 checks:

- `eval` and `new Function`
- Browser or request input written as HTML
- Request input added to SQL query text
- Request input passed to shell commands
- Secret-looking values written in the source
- Disabled TLS certificate checks
- MD5 or SHA-1 used for hashing
- Wildcard CORS with credentials
- `Math.random()` used for token-like values
- JWT verification configured to accept the `none` algorithm

Findings include the source location, code excerpt, severity, CWE number, and a suggested fix.

## Requirements

- Node.js 24
- npm

## Run locally

```sh
npm install
npm run dev
```

## Test and build

```sh
npm test
npm run typecheck
npm run build
```

The production site is written to `dist`.

## Upload to Netlify

You can publish the built site without connecting GitHub:

1. Run `npm install` and `npm run build`.
2. Sign in at [Netlify Drop](https://app.netlify.com/drop).
3. Drag the `dist` folder onto the page.
4. Open the site URL Netlify shows when the upload finishes.

To publish a newer version, build again and upload the new `dist` folder.

## How it works

TraceGuard uses the TypeScript parser to read code and apply its rules. The source is processed in the browser. There is no analysis server.

The analyzer tracks a few simple input paths inside one file. It does not follow every value through every function or across files. Its confidence numbers are estimates, not measured probabilities. The score helps sort findings. It is not a security rating.

## Files

- `src/lib/analyzer.ts` contains the rules and analysis code.
- `src/App.tsx` contains the editor and results screen.
- `tests/analyzer.test.mjs` contains safe and unsafe examples.
- `netlify.toml` sets the publish folder for a Netlify build.
