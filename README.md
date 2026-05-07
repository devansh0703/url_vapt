# URL VAPT Scanner

This project provides a URL/domain security scanning workflow with:

- A **Next.js frontend** for selecting scanners and downloading reports.
- A **FastAPI backend** that runs multiple scans and returns a generated PDF report.

## Project Structure

### `app/` (Next.js frontend)

- `app/page.tsx`  
  Main UI for:
  - Entering target URL/domain
  - Selecting scanners (`whois`, `virustotal`, `security_headers`, `crtsh`, `bgpview`, `ssllabs`, `urlscan`, `publicwww`)
  - Sending POST request to `http://127.0.0.1:8000/generate-report`
  - Previewing and downloading the generated PDF
- `app/layout.tsx`  
  Root layout and metadata setup for the frontend.
- `app/globals.css`  
  Global styles.

### `main.py` (FastAPI backend)

`main.py` exposes the backend API and report generation logic:

- Initializes FastAPI app with CORS for local frontend origins.
- Defines async scanner wrappers and scanner functions for:
  - WHOIS
  - VirusTotal
  - SSL Labs
  - crt.sh
  - Security Headers
  - urlscan.io
  - PublicWWW (via Selenium)
  - BGPView
- Maps scanners with `SCANNER_MAP`.
- Exposes endpoint:
  - `POST /generate-report`
    - Input: `{ "target": "...", "scanners": ["whois", ...] }`
    - Output: generated PDF report file response
- Generates report content using Gemini, converts Markdown → HTML, and renders a styled PDF via ReportLab.

## Run Locally

### Frontend

```bash
npm install
npm run dev
```

Frontend runs on `http://localhost:3000`.

### Backend

Run the FastAPI app from repository root (example with uvicorn):

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Backend runs on `http://127.0.0.1:8000`.

## Notes

- The frontend currently calls the backend at `http://127.0.0.1:8000/generate-report`.
- `GEMINI_API_KEY` is required in environment variables for report generation.
