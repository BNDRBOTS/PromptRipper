### `README.md`

```markdown
# Prompt Ripper Pro — Forensic Edition

Production-grade prompt extraction and analysis tool with a web interface. Supports fuzzy matching for speech-to-text errors, multiple file formats, red-team risk detection, and hybrid semantic search.

## Features

- Upload: TXT, MD, JSON, CSV, LOG, PDF, DOCX, PNG, JPG, JPEG, TIFF, BMP, WEBP
- OCR via Tesseract with multi-variant preprocessing and adaptive PSM selection
- Fuzzy label matching using `rapidfuzz` (handles STT misrecognitions)
- Structural prompt-boundary detection
- Prompt probability scoring via logistic regression on linguistic features
- Utility scoring
- Red-team forensic risk classification with evidence
- Exact, near-text, and semantic deduplication
- Hybrid search: BM25 + character n-grams + semantic embeddings + cross-encoder reranking
- Real-time progress via Server-Sent Events
- Dark/light mode toggle
- Mobile-responsive design

## Requirements

- Python 3.9+
- Tesseract OCR installed on the system
  - Ubuntu/Debian: `sudo apt install tesseract-ocr`
  - macOS: `brew install tesseract`
  - Windows: Download from [UB-Mannheim/tesseract](https://github.com/UB-Mannheim/tesseract/wiki)
- For PDF OCR: `poppler-utils` may be required (`sudo apt install poppler-utils`)

## Installation

1. Clone the repository.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure Tesseract is in your PATH.

## Running Locally

```bash
python app.py
```

Open http://localhost:5000 in your browser.

## Deploying to Railway

### Option A: Dockerfile (recommended)

The included `Dockerfile` installs Tesseract and all dependencies. Push the repository to GitHub and connect it to Railway. Railway will automatically detect the Dockerfile and build the image.

### Option B: Nixpacks with Tesseract

Create a `nixpacks.toml` file in the repository root:

```toml
[phases.setup]
nixPkgs = ["tesseract"]
```

Then the provided `railway.json` will handle the build. Set the `PORT` environment variable (Railway provides it automatically). The healthcheck endpoint `/health` verifies upload folder, Tesseract, and the ripper module.

## API Endpoints

- `POST /upload` – Upload file with options (`min_prompt_probability`, `min_utility`). Returns `job_id`.
- `GET /stream/{job_id}` – SSE stream for progress updates.
- `GET /results/{job_id}` – Get final JSON results.
- `GET /search?q=...&top_k=10` – Hybrid search across extracted prompts.
- `POST /build_index` – Rebuild search index (expects `{"prompts": [...]}`).
- `GET /health` – Health check with real dependency verification.

## Data Flow

1. File uploaded.
2. Text extracted based on file type (native PDF text or OCR, DOCX, JSON, CSV, plain text, images).
3. Candidate generation from structural and linguistic signals.
4. Risk classification (forensic, non-destructive).
5. Deduplication (exact, near-text, semantic).
6. Search indices built (BM25, char n-grams, semantic embeddings).
7. Frontend displays results and allows hybrid search.

## Security Notes

- Uploaded files are stored in a temporary directory and deleted after processing.
- All processing is local; no external API calls are made.
- Risk classification is forensic: the original content is preserved verbatim and risk labels are attached as evidence.

## License

MIT
```
