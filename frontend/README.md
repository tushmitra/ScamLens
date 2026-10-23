# ScamLens Frontend

A responsive React + TypeScript + Vite interface for the ScamLens experimental message and static-URL screening API.

## Run locally

```bash
npm install
cp .env.example .env
npm run dev
```

Set `VITE_SCAMLENS_API_URL` in `.env` to the base URL of the FastAPI backend (for example, `http://127.0.0.1:8000`). Restart Vite after changing `.env`.

## Verify

```bash
npm test
npm run build
```

## UI details

- Midnight cybersecurity visual style with animated ambient glows, grid texture, orbiting shield illustration, and a custom SVG brand mark.
- Responsive scanner layout with a prefilled sample message, character count, loading state, retryable errors, and API-backed result panel.
- CSS animations respect `prefers-reduced-motion`.
- The sample is not analyzed until the user clicks **Analyze message** and the configured API returns a valid response.
- Submitted URLs are rendered as text and are not automatically opened.

## Important limitations

ScamLens is experimental screening, not proof that a message is fraudulent or safe. The model score is shown as an experimental signal and should not be treated as a verified probability unless the API explicitly reports calibration.

## API contract

The UI calls `POST {VITE_SCAMLENS_API_URL}/check`; the response shape is documented in `../docs/API.md` and mirrored in
`src/types/api.ts`. When the server has no text model, `model_scam_score`/`model_scam_score_percent` are `null` and the
UI says so instead of showing a score. The optional `advice` array is rendered as "What to do next".

Vite variables are public and baked into the bundle; never put secrets in them. The stylesheet imports Google Fonts
(a third-party request on page load); self-host the fonts if that matters for your deployment.
