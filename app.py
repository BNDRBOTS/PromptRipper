from __future__ import annotations
import json
import os
import queue
import shutil
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import faiss
import numpy as np
import scipy.sparse as sp
import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from rank_bm25 import BM25Okapi
from sentence_transformers import CrossEncoder, SentenceTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from ripper import PromptRipper

UPLOAD_FOLDER = Path(tempfile.mkdtemp(prefix="prompt_ripper_"))
MAX_FILE_SIZE = 50 * 1024 * 1024
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
RERANK_MODEL = os.getenv("RERANK_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")
ENABLE_RERANKER = os.getenv("ENABLE_RERANKER", "1") == "1"

app = FastAPI(title="Prompt Ripper Pro — Forensic Edition")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

jobs: Dict[str, Dict[str, Any]] = {}
jobs_lock = threading.Lock()

embedding_model: Optional[SentenceTransformer] = None
reranker: Optional[CrossEncoder] = None
semantic_index: Optional[faiss.Index] = None
semantic_documents: List[Dict[str, Any]] = []
bm25: Optional[BM25Okapi] = None
bm25_tokens: List[List[str]] = []
char_vectorizer: Optional[TfidfVectorizer] = None
char_matrix: Optional[sp.csr_matrix] = None
index_lock = threading.RLock()

class IndexRequest(BaseModel):
    prompts: List[Dict[str, Any]]

def lexical_tokens(text: str) -> List[str]:
    import re
    # Do not delete stopwords. Negation and instruction words matter in prompts.
    return re.findall(
        r"[A-Za-z0-9_./\\:{}<>\[\]-]+",
        text.casefold(),
    )

def searchable_text(prompt: Dict[str, Any]) -> str:
    flags = " ".join(prompt.get("risk_flags", []))
    detectors = " ".join(prompt.get("detector_hits", []))
    return (
        f"Heading: {prompt.get('heading_path', '')}\n"
        f"Type: {prompt.get('source_type', '')}\n"
        f"Risk flags: {flags}\n"
        f"Detector evidence: {detectors}\n"
        f"Prompt:\n{prompt.get('content', '')}"
    )

def semantic_chunks(
    prompt: Dict[str, Any],
    max_words: int = 220,
    overlap_words: int = 45,
) -> List[str]:
    base = searchable_text(prompt)
    words = base.split()
    if len(words) <= max_words:
        return [base]
    chunks = [base]  # preserve whole-prompt representation
    step = max_words - overlap_words
    for start in range(0, len(words), step):
        chunk = words[start : start + max_words]
        if not chunk:
            break
        chunks.append(" ".join(chunk))
        if start + max_words >= len(words):
            break
    return chunks

def build_search_index(prompts: List[Dict[str, Any]]) -> None:
    global semantic_index
    global semantic_documents
    global bm25
    global bm25_tokens
    global char_vectorizer
    global char_matrix
    global embedding_model
    with index_lock:
        semantic_documents = []
        if not prompts:
            semantic_index = None
            bm25 = None
            char_vectorizer = None
            char_matrix = None
            return
        if embedding_model is None:
            embedding_model = SentenceTransformer(EMBEDDING_MODEL)
        semantic_texts = []
        for prompt_idx, prompt in enumerate(prompts):
            chunks = semantic_chunks(prompt)
            for chunk_idx, chunk in enumerate(chunks):
                semantic_texts.append(chunk)
                semantic_documents.append(
                    {
                        "prompt_idx": prompt_idx,
                        "chunk_idx": chunk_idx,
                        "is_whole_prompt": chunk_idx == 0,
                    }
                )
        vectors = embedding_model.encode(
            semantic_texts,
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        ).astype(np.float32)
        semantic_index = faiss.IndexFlatIP(vectors.shape[1])
        semantic_index.add(vectors)
        lexical_documents = [searchable_text(p) for p in prompts]
        bm25_tokens = [lexical_tokens(text) for text in lexical_documents]
        bm25 = BM25Okapi(bm25_tokens)
        char_vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=1,
            sublinear_tf=True,
            norm="l2",
        )
        char_matrix = char_vectorizer.fit_transform(lexical_documents)

def rank_semantic(
    query: str,
    prompts: List[Dict[str, Any]],
    candidate_count: int,
) -> List[Dict[str, Any]]:
    if semantic_index is None or embedding_model is None:
        return []
    vector = embedding_model.encode(
        [query],
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    ).astype(np.float32)
    search_k = min(
        max(candidate_count * 5, candidate_count),
        len(semantic_documents),
    )
    scores, indices = semantic_index.search(vector, search_k)
    parent_scores: Dict[int, Dict[str, float]] = {}
    for score, index in zip(scores[0], indices[0]):
        if index < 0 or index >= len(semantic_documents):
            continue
        metadata = semantic_documents[index]
        prompt_idx = metadata["prompt_idx"]
        value = float(score)
        state = parent_scores.setdefault(
            prompt_idx,
            {
                "max_chunk": -1.0,
                "whole": -1.0,
            },
        )
        state["max_chunk"] = max(state["max_chunk"], value)
        if metadata["is_whole_prompt"]:
            state["whole"] = max(state["whole"], value)
    results = []
    for prompt_idx, state in parent_scores.items():
        whole = max(state["whole"], 0.0)
        score = state["max_chunk"] + 0.15 * whole
        results.append(
            {
                "prompt_idx": prompt_idx,
                "score": score,
            }
        )
    results.sort(key=lambda x: -x["score"])
    return results[:candidate_count]

def rank_bm25(
    query: str,
    candidate_count: int,
) -> List[Dict[str, Any]]:
    if bm25 is None:
        return []
    scores = bm25.get_scores(lexical_tokens(query))
    indices = np.argsort(scores)[::-1]
    out = []
    for idx in indices[:candidate_count]:
        out.append(
            {
                "prompt_idx": int(idx),
                "score": float(scores[idx]),
            }
        )
    return out

def rank_char(
    query: str,
    candidate_count: int,
) -> List[Dict[str, Any]]:
    if char_vectorizer is None or char_matrix is None:
        return []
    query_vec = char_vectorizer.transform([query])
    scores = (query_vec @ char_matrix.T).toarray().ravel()
    indices = np.argsort(scores)[::-1]
    out = []
    for idx in indices[:candidate_count]:
        if scores[idx] <= 0:
            continue
        out.append(
            {
                "prompt_idx": int(idx),
                "score": float(scores[idx]),
            }
        )
    return out

def reciprocal_rank_fusion(
    rankings: List[List[Dict[str, Any]]],
    k: int = 60,
) -> List[Dict[str, Any]]:
    fused: Dict[int, Dict[str, Any]] = {}
    for ranking_name, ranking in enumerate(rankings):
        for rank, item in enumerate(ranking, 1):
            prompt_idx = item["prompt_idx"]
            entry = fused.setdefault(
                prompt_idx,
                {
                    "prompt_idx": prompt_idx,
                    "rrf_score": 0.0,
                    "source_ranks": {},
                    "source_scores": {},
                },
            )
            entry["rrf_score"] += 1.0 / (k + rank)
            entry["source_ranks"][str(ranking_name)] = rank
            entry["source_scores"][str(ranking_name)] = item["score"]
    return sorted(
        fused.values(),
        key=lambda x: -x["rrf_score"],
    )

def rerank_results(
    query: str,
    fused: List[Dict[str, Any]],
    prompts: List[Dict[str, Any]],
    final_k: int,
) -> List[Dict[str, Any]]:
    global reranker
    candidates = fused[: max(final_k * 3, 30)]
    if not ENABLE_RERANKER:
        return candidates[:final_k]
    try:
        if reranker is None:
            reranker = CrossEncoder(RERANK_MODEL)
        pairs = [
            [query, searchable_text(prompts[item["prompt_idx"]])]
            for item in candidates
        ]
        rerank_scores = reranker.predict(pairs)
        for item, score in zip(candidates, rerank_scores):
            item["rerank_score"] = float(score)
        candidates.sort(key=lambda x: -x["rerank_score"])
    except Exception:
        # Retrieval remains functional when the optional reranker is unavailable.
        pass
    return candidates[:final_k]

def hybrid_search(
    query: str,
    prompts: List[Dict[str, Any]],
    top_k: int,
) -> List[Dict[str, Any]]:
    broad_k = min(max(top_k * 4, 40), max(len(prompts), 1))
    semantic = rank_semantic(query, prompts, broad_k)
    lexical = rank_bm25(query, broad_k)
    char = rank_char(query, broad_k)
    fused = reciprocal_rank_fusion(
        [semantic, lexical, char],
        k=60,
    )
    ranked = rerank_results(
        query,
        fused,
        prompts,
        top_k,
    )
    output = []
    for rank, item in enumerate(ranked, 1):
        output.append(
            {
                "rank": rank,
                "prompt": prompts[item["prompt_idx"]],
                "score": item.get(
                    "rerank_score",
                    item["rrf_score"],
                ),
                "rrf_score": item["rrf_score"],
                "source_ranks": item["source_ranks"],
                "source_scores": item["source_scores"],
                "method": "hybrid",
            }
        )
    return output

def worker(
    job_id: str,
    input_path: Path,
    min_prompt_probability: float,
    min_utility: int,
) -> None:
    job = jobs[job_id]
    q = job["queue"]
    try:
        q.put(
            {
                "type": "status",
                "message": "Extracting structured document evidence...",
            }
        )
        engine = PromptRipper(
            minimum_prompt_probability=min_prompt_probability,
            minimum_utility=min_utility,
            keep_low_probability=True,
        )
        report = engine.process(input_path)
        q.put(
            {
                "type": "progress",
                "message": (
                    f"Detected {report['metadata']['accepted_prompt_count']} "
                    "prompt candidates."
                ),
            }
        )
        q.put(
            {
                "type": "status",
                "message": "Building BM25, character and semantic indices...",
            }
        )
        build_search_index(report["prompts"])
        with jobs_lock:
            job["result"] = report
            job["status"] = "completed"
        q.put(
            {
                "type": "result",
                "data": report,
            }
        )
        q.put(
            {
                "type": "done",
                "message": "Forensic processing complete.",
            }
        )
    except Exception as exc:
        with jobs_lock:
            job["status"] = "error"
            job["error"] = str(exc)
        q.put(
            {
                "type": "error",
                "message": str(exc),
            }
        )
    finally:
        try:
            input_path.unlink(missing_ok=True)
        except Exception:
            pass

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request},
    )

@app.post("/upload")
async def upload(
    file: UploadFile = File(...),
    min_prompt_probability: float = Form(0.35),
    min_utility: int = Form(0),
):
    if not 0 <= min_prompt_probability <= 1:
        raise HTTPException(
            400,
            "min_prompt_probability must be between 0 and 1",
        )
    allowed = {
        ".txt",
        ".md",
        ".json",
        ".csv",
        ".log",
        ".pdf",
        ".docx",
        ".png",
        ".jpg",
        ".jpeg",
        ".tif",
        ".tiff",
        ".bmp",
        ".webp",
    }
    filename = file.filename or "upload.txt"
    extension = Path(filename).suffix.lower()
    if extension not in allowed:
        raise HTTPException(
            400,
            f"Unsupported file extension: {extension}",
        )
    job_id = str(uuid.uuid4())
    target = UPLOAD_FOLDER / f"{job_id}{extension}"
    size = 0
    with target.open("wb") as output:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_SIZE:
                output.close()
                target.unlink(missing_ok=True)
                raise HTTPException(
                    413,
                    "File exceeds 50 MB limit.",
                )
            output.write(chunk)
    with jobs_lock:
        jobs[job_id] = {
            "queue": queue.Queue(),
            "status": "running",
            "result": None,
            "error": None,
        }
    thread = threading.Thread(
        target=worker,
        args=(
            job_id,
            target,
            min_prompt_probability,
            min_utility,
        ),
        daemon=True,
    )
    thread.start()
    return JSONResponse(
        {"job_id": job_id},
        status_code=202,
    )

@app.get("/stream/{job_id}")
async def stream(job_id: str):
    if job_id not in jobs:
        raise HTTPException(404, "Invalid job ID")
    async def events():
        q = jobs[job_id]["queue"]
        while True:
            try:
                message = q.get(timeout=25)
                yield f"data: {json.dumps(message)}\n\n"
                if message["type"] in {"done", "error"}:
                    break
            except queue.Empty:
                yield ": keep-alive\n\n"
    return StreamingResponse(
        events(),
        media_type="text/event-stream",
    )

@app.get("/results/{job_id}")
async def results(job_id: str):
    if job_id not in jobs:
        raise HTTPException(404, "Invalid job ID")
    job = jobs[job_id]
    if job["status"] == "completed":
        return JSONResponse(job["result"])
    if job["status"] == "error":
        raise HTTPException(
            500,
            job.get("error") or "Processing failed",
        )
    return JSONResponse(
        {"status": "processing"},
        status_code=202,
    )

@app.get("/search")
async def search(
    q: str = Query(..., min_length=1),
    top_k: int = Query(10, ge=1, le=50),
):
    completed = [
        job
        for job in jobs.values()
        if job.get("status") == "completed"
        and job.get("result")
    ]
    if not completed:
        raise HTTPException(
            404,
            "No processed prompt collection is currently indexed.",
        )
    prompts = completed[-1]["result"]["prompts"]
    if not prompts:
        return JSONResponse([])
    with index_lock:
        output = hybrid_search(
            q,
            prompts,
            top_k,
        )
    return JSONResponse(output)

@app.post("/build_index")
async def build_index(request: IndexRequest):
    build_search_index(request.prompts)
    return JSONResponse(
        {
            "status": "index built",
            "prompt_count": len(request.prompts),
        }
    )

@app.get("/health")
async def health():
    checks = {
        "upload_folder": UPLOAD_FOLDER.is_dir(),
        "ripper_module": True,
        "tesseract": False,
        "semantic_model": embedding_model is not None,
    }
    try:
        pytesseract.get_tesseract_version()
        checks["tesseract"] = True
    except Exception:
        pass
    critical = (
        checks["upload_folder"]
        and checks["ripper_module"]
    )
    return JSONResponse(
        {
            "status": "healthy" if critical else "unhealthy",
            "checks": checks,
        },
        status_code=200 if critical else 500,
    )

@app.on_event("startup")
async def startup():
    global embedding_model
    UPLOAD_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )
    try:
        embedding_model = SentenceTransformer(
            EMBEDDING_MODEL,
        )
    except Exception:
        embedding_model = None

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        log_level="info",
    )
