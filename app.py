import os
import subprocess
import tempfile
import threading
import uuid
import queue
import json
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any

import uvicorn
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Query, Request
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import fitz  # PyMuPDF
from docx import Document
from PIL import Image
import pytesseract
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import scipy.sparse as sp

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
UPLOAD_FOLDER = tempfile.mkdtemp()
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
MODEL_NAME = 'all-MiniLM-L6-v2'   # Lightweight semantic model

# Global job storage
jobs: Dict[str, Dict[str, Any]] = {}
jobs_lock = threading.Lock()

# Global search indices (in-memory)
semantic_model: Optional[SentenceTransformer] = None
tfidf_vectorizer: Optional[TfidfVectorizer] = None
faiss_index: Optional[faiss.Index] = None
tfidf_matrix: Optional[sp.csr_matrix] = None
results_metadata: List[Dict[str, Any]] = []

app = FastAPI(title="Prompt Ripper Pro")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ----------------------------------------------------------------------
# Text extraction functions
# ----------------------------------------------------------------------
def extract_text_from_pdf(file_path: str) -> str:
    text = ""
    with fitz.open(file_path) as doc:
        for page in doc:
            text += page.get_text()
    return text

def extract_text_from_docx(file_path: str) -> str:
    doc = Document(file_path)
    return "\n".join([para.text for para in doc.paragraphs])

def extract_text_from_image(file_path: str) -> str:
    img = Image.open(file_path)
    return pytesseract.image_to_string(img)

def extract_text_from_plain(file_path: str) -> str:
    for enc in ["utf-8", "cp1252", "latin-1"]:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def extract_text(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if ext == '.pdf':
        return extract_text_from_pdf(file_path)
    elif ext == '.docx':
        return extract_text_from_docx(file_path)
    elif ext in ['.png', '.jpg', '.jpeg', '.tiff', '.bmp']:
        return extract_text_from_image(file_path)
    else:
        return extract_text_from_plain(file_path)

# ----------------------------------------------------------------------
# Search index building
# ----------------------------------------------------------------------
def build_search_index(prompts: List[Dict[str, Any]]):
    """Build semantic (FAISS) and lexical (TF‑IDF) indices in memory."""
    global semantic_model, tfidf_vectorizer, faiss_index, tfidf_matrix, results_metadata

    results_metadata = prompts
    if not prompts:
        return

    # Semantic index
    if semantic_model is None:
        semantic_model = SentenceTransformer(MODEL_NAME)
    embeddings = semantic_model.encode([p['content'] for p in prompts], convert_to_numpy=True)
    dimension = embeddings.shape[1]
    faiss_index = faiss.IndexFlatL2(dimension)
    faiss_index.add(embeddings.astype(np.float32))

    # Lexical index
    tfidf_vectorizer = TfidfVectorizer(stop_words='english', max_features=10000)
    tfidf_matrix = tfidf_vectorizer.fit_transform([p['content'] for p in prompts])

# ----------------------------------------------------------------------
# Background processing
# ----------------------------------------------------------------------
def run_ripper(job_id: str, input_path: str, output_path: str,
               similarity: float, min_utility: int, keep_duplicates: bool):
    q = jobs[job_id]['queue']
    q.put({'type': 'status', 'message': 'Starting text extraction...'})

    cmd = [
        'python', 'ripper.py', input_path, output_path,
        '--similarity', str(similarity),
        '--min-utility', str(min_utility)
    ]
    if keep_duplicates:
        cmd.append('--keep-duplicates')

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True
    )

    for line in iter(process.stderr.readline, ''):
        if line:
            line = line.rstrip()
            if line:
                q.put({'type': 'progress', 'message': line})

    process.wait()
    if process.returncode != 0:
        q.put({'type': 'error', 'message': f'Script failed with exit code {process.returncode}'})
        jobs[job_id]['status'] = 'error'
        return

    try:
        with open(output_path, 'r', encoding='utf-8') as f:
            results = json.load(f)
        jobs[job_id]['result'] = results
        jobs[job_id]['status'] = 'completed'

        # Build search indices in background thread to avoid blocking
        build_search_index(results)

        q.put({'type': 'result', 'data': results})
        q.put({'type': 'done', 'message': 'Processing complete.'})
    except Exception as e:
        q.put({'type': 'error', 'message': f'Error reading results: {str(e)}'})
        jobs[job_id]['status'] = 'error'

# ----------------------------------------------------------------------
# API Endpoints
# ----------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    similarity: float = Form(0.92),
    min_utility: int = Form(0),
    keep_duplicates: bool = Form(False)
):
    job_id = str(uuid.uuid4())
    ext = Path(file.filename).suffix.lower()
    allowed_exts = ['.txt', '.md', '.json', '.csv', '.log', '.pdf', '.docx', '.png', '.jpg', '.jpeg', '.tiff', '.bmp']
    if ext not in allowed_exts:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}")

    # Save uploaded file
    input_path = os.path.join(UPLOAD_FOLDER, f"{job_id}{ext}")
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Extract text
    try:
        text = extract_text(input_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Text extraction failed: {str(e)}")

    # Save text as a temporary .txt file for ripper.py
    text_file_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_extracted.txt")
    with open(text_file_path, 'w', encoding='utf-8') as f:
        f.write(text)

    output_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_output.json")

    with jobs_lock:
        jobs[job_id] = {
            'queue': queue.Queue(),
            'status': 'running',
            'result': None,
            'error': None,
        }

    thread = threading.Thread(
        target=run_ripper,
        args=(job_id, text_file_path, output_path, similarity, min_utility, keep_duplicates)
    )
    thread.daemon = True
    thread.start()

    return JSONResponse({"job_id": job_id}, status_code=202)

@app.get("/stream/{job_id}")
async def stream(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Invalid job ID")

    async def event_generator():
        q = jobs[job_id]['queue']
        while True:
            try:
                message = q.get(timeout=30)
                yield f"data: {json.dumps(message)}\n\n"
                if message['type'] in ('done', 'error'):
                    break
            except queue.Empty:
                yield ": keep-alive\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/results/{job_id}")
async def get_results(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Invalid job ID")
    job = jobs[job_id]
    if job['status'] == 'completed':
        return JSONResponse(job['result'])
    elif job['status'] == 'error':
        raise HTTPException(status_code=500, detail=job.get('error', 'Processing error'))
    else:
        return JSONResponse({"status": "processing"}, status_code=202)

@app.get("/search")
async def search_prompts(
    q: str = Query(..., min_length=1),
    method: str = Query("semantic", regex="^(semantic|lexical|both)$"),
    top_k: int = Query(10, ge=1, le=50)
):
    if not results_metadata:
        raise HTTPException(status_code=404, detail="No prompts indexed yet. Process a file first.")

    results = []
    if method in ("semantic", "both") and faiss_index is not None:
        query_embedding = semantic_model.encode([q], convert_to_numpy=True).astype(np.float32)
        distances, indices = faiss_index.search(query_embedding, top_k)
        for idx, dist in zip(indices[0], distances[0]):
            if idx < len(results_metadata):
                results.append({
                    "prompt": results_metadata[idx],
                    "score": float(dist),
                    "method": "semantic"
                })

    if method in ("lexical", "both") and tfidf_vectorizer is not None and tfidf_matrix is not None:
        query_vec = tfidf_vectorizer.transform([q])
        similarities = cosine_similarity(query_vec, tfidf_matrix).flatten()
        top_indices = similarities.argsort()[-top_k:][::-1]
        for idx in top_indices:
            if similarities[idx] > 0:
                results.append({
                    "prompt": results_metadata[idx],
                    "score": float(similarities[idx]),
                    "method": "lexical"
                })

    if method == "semantic":
        results.sort(key=lambda x: x['score'])
    elif method == "lexical":
        results.sort(key=lambda x: -x['score'])
    else:  # both
        results.sort(key=lambda x: (x['method'], x['score'] if x['method']=='semantic' else -x['score']))

    return JSONResponse(results[:top_k])

@app.post("/build_index")
async def build_index_endpoint(prompts: List[Dict[str, Any]]):
    build_search_index(prompts)
    return JSONResponse({"status": "index built"})

@app.get("/health")
async def health_check():
    """Real healthcheck: verifies that the temporary directory exists and is writable."""
    checks = {}
    if os.path.isdir(UPLOAD_FOLDER) and os.access(UPLOAD_FOLDER, os.W_OK):
        checks['temp_dir'] = 'ok'
    else:
        checks['temp_dir'] = 'error: upload folder missing or not writable'
    try:
        pytesseract.get_tesseract_version()
        checks['tesseract'] = 'ok'
    except Exception as e:
        checks['tesseract'] = f'warning: {str(e)}'
    if os.path.isfile('ripper.py'):
        checks['ripper_script'] = 'ok'
    else:
        checks['ripper_script'] = 'error: ripper.py not found'

    critical_fail = any(v.startswith('error') for v in checks.values())
    if critical_fail:
        return JSONResponse({"status": "unhealthy", "checks": checks}, status_code=500)
    return JSONResponse({"status": "healthy", "checks": checks}, status_code=200)

@app.on_event("startup")
async def startup_event():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")
