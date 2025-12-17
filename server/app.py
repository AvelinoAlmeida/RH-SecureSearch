# -*- coding:utf-8 _*-
"""
Servidor 'não confiável' para a demo de Searchable Symmetric Encryption (SSE).

Guarda:
  - documentos cifrados em storage/docs/*.json
  - índice invertido por trapdoor em storage/index.json
  - estatísticas de leakage (número de pesquisas por trapdoor) em storage/stats/search_stats.json
  - métricas do cliente em storage/stats/metrics.csv (produzido pelo cliente)
  - métricas do servidor em storage/stats/server_metrics.csv (produzido pelo servidor)

Rotas principais:
  - GET/POST /        : vista do servidor (apenas trapdoors/docIds)
  - GET       /stats  : leakage de pesquisas (trapdoors + contagens)
  - GET       /metrics: métricas de desempenho (metrics.csv)
  - GET/POST /client  : vista do cliente (simulada; sem chave real)
  - POST     /upload  : upload de índice e docs cifrados
  - POST     /search  : pesquisa por trapdoor (por defeito devolve só docIds)
  - GET      /doc/<id>: obter um doc cifrado (nonce+ciphertext)
"""

import csv
import json
import os
import re
import time
from datetime import datetime
from threading import Lock
from flask import Flask, request, jsonify, render_template

APP = Flask(__name__)

# -------------------------
# Diretórios do projeto
# -------------------------

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_DIR = os.path.join(PROJECT_DIR, "storage")
DOCS_DIR = os.path.join(STORAGE_DIR, "docs")
STATS_DIR = os.path.join(STORAGE_DIR, "stats")

os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(STATS_DIR, exist_ok=True)

INDEX_PATH = os.path.join(STORAGE_DIR, "index.json")
SEARCH_STATS_PATH = os.path.join(STATS_DIR, "search_stats.json")
METRICS_PATH = os.path.join(STATS_DIR, "metrics.csv")
SERVER_METRICS_PATH = os.path.join(STATS_DIR, "server_metrics.csv")

# Locks simples (úteis em modo threaded)
INDEX_LOCK = Lock()
STATS_LOCK = Lock()
SERVER_METRICS_LOCK = Lock()

# -------------------------
# Validação e limites
# -------------------------

# Trapdoor hex (HMAC-SHA256) costuma ter 64 hex chars; aceitamos intervalo para tolerância.
TRAPDOOR_RE = re.compile(r"^[0-9a-fA-F]{32,256}$")
# Doc IDs controlados (ajusta ao vosso dataset). Evita path traversal e nomes arbitrários.
DOC_ID_RE = re.compile(r"^emp_\d{3,6}$")  # ex.: emp_001 ... emp_123456

MAX_UPLOAD_TERMS = 200_000     # para demo; ajusta ao vosso caso
MAX_UPLOAD_DOCS = 50_000
MAX_DOCIDS_PER_TERM = 50_000   # limita listas enormes por trapdoor
MAX_TRAPDOOR_LEN = 512         # hard cap defensivo

# -------------------------
# Helpers: I/O atómico
# -------------------------

def safe_write_json_atomic(path: str, data: dict) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def safe_read_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# -------------------------
# Helpers: índice cifrado
# -------------------------

def load_index() -> dict:
    """Carrega index.json: trapdoorHex -> [docId, ...]."""
    return safe_read_json(INDEX_PATH)

def save_index(index: dict) -> None:
    safe_write_json_atomic(INDEX_PATH, index)

# -------------------------
# Helpers: leakage pesquisas
# -------------------------

def load_search_stats() -> dict:
    """search_stats.json: trapdoorHex -> count."""
    return safe_read_json(SEARCH_STATS_PATH)

def save_search_stats(stats: dict) -> None:
    safe_write_json_atomic(SEARCH_STATS_PATH, stats)

# -------------------------
# Helpers: métricas do servidor
# -------------------------

def ensure_server_metrics_header() -> None:
    if os.path.exists(SERVER_METRICS_PATH):
        return
    with open(SERVER_METRICS_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts_iso", "method", "path", "status_code", "duration_ms", "remote_addr"])

def append_server_metric(method: str, path: str, status_code: int, duration_ms: float, remote_addr: str) -> None:
    with SERVER_METRICS_LOCK:
        ensure_server_metrics_header()
        with open(SERVER_METRICS_PATH, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([datetime.utcnow().isoformat(), method, path, status_code, round(duration_ms, 3), remote_addr])

@APP.before_request
def _t0():
    request._t0 = time.perf_counter()

@APP.after_request
def _metrics(response):
    try:
        t0 = getattr(request, "_t0", None)
        if t0 is not None:
            dt_ms = (time.perf_counter() - t0) * 1000.0
            append_server_metric(
                method=request.method,
                path=request.path,
                status_code=response.status_code,
                duration_ms=dt_ms,
                remote_addr=request.headers.get("X-Forwarded-For", request.remote_addr) or ""
            )
    except Exception:
        # Nunca rebentar a resposta por causa de logging
        pass
    return response

# -------------------------
# Helpers: validação
# -------------------------

def is_valid_trapdoor(t: str) -> bool:
    if not isinstance(t, str):
        return False
    if len(t) == 0 or len(t) > MAX_TRAPDOOR_LEN:
        return False
    return bool(TRAPDOOR_RE.match(t))

def is_valid_doc_id(doc_id: str) -> bool:
    return isinstance(doc_id, str) and bool(DOC_ID_RE.match(doc_id))

def doc_path(doc_id: str) -> str:
    # doc_id já validado por regex; evita traversal.
    return os.path.join(DOCS_DIR, f"{doc_id}.json")

# -------------------------
# Vistas HTML
# -------------------------

@APP.route("/", methods=["GET", "POST"])
def home():
    """
    Vista do servidor:
      - formulário simples
      - se receber um docId (emp_001) mostra só se existe
      - se receber um trapdoor, mostra apenas docIds associados
    """
    term = ""
    results = []

    if request.method == "POST":
        term = request.form.get("term", "").strip()

        if term.startswith("emp_"):
            if is_valid_doc_id(term) and os.path.exists(doc_path(term)):
                results = [term]
            else:
                results = []
        else:
            if is_valid_trapdoor(term):
                index = load_index()
                results = index.get(term, [])
            else:
                results = []

    return render_template("home.html", term=term, results=results)

@APP.get("/stats")
def stats_page():
    """Mostra leakage: trapdoor + número de pesquisas."""
    stats = load_search_stats()
    rows = sorted(stats.items(), key=lambda x: x[1], reverse=True)
    return render_template("stats.html", rows=rows)

@APP.get("/metrics")
def metrics_page():
    """Mostra storage/stats/metrics.csv como tabela HTML."""
    headers = []
    rows = []

    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i == 0:
                    headers = row
                else:
                    rows.append(row)

    return render_template("metrics.html", headers=headers, rows=rows)

@APP.route("/client", methods=["GET", "POST"])
def client_view():
    """
    Vista do cliente (simulada para a demo web):
      - aqui *não* se guarda chave; a descifra real continua no client.py
      - serve apenas para mostrar a fronteira conceptual entre servidor e cliente
    """
    term = ""
    docs = {}  # mantido vazio para não violar o modelo de ameaça

    if request.method == "POST":
        term = request.form.get("term", "").strip()

    return render_template("client.html", term=term, docs=docs)

# -------------------------
# API JSON
# -------------------------

@APP.get("/health")
def health():
    return jsonify({"status": "ok"})

@APP.post("/upload")
def upload():
    """
    Recebe:
      {
        "index": { trapdoorHex: [docId, ...] },
        "docs":  { docId: { nonce:..., ciphertext:... }, ... }
      }

    Faz merge do índice e grava documentos cifrados.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "error": "invalid_json"}), 400

    index_in = payload.get("index", {})
    docs_in = payload.get("docs", {})

    if not isinstance(index_in, dict) or not isinstance(docs_in, dict):
        return jsonify({"status": "error", "error": "invalid_payload_shape"}), 400

    if len(index_in) > MAX_UPLOAD_TERMS:
        return jsonify({"status": "error", "error": "too_many_terms"}), 413

    if len(docs_in) > MAX_UPLOAD_DOCS:
        return jsonify({"status": "error", "error": "too_many_docs"}), 413

    # 1) Merge do índice com validação
    with INDEX_LOCK:
        index = load_index()
        accepted_terms = 0
        accepted_pairs = 0

        for t, doc_ids in index_in.items():
            if not is_valid_trapdoor(t):
                continue
            if not isinstance(doc_ids, list):
                continue

            # filtra doc ids válidos e limita
            filtered = []
            for d in doc_ids[:MAX_DOCIDS_PER_TERM]:
                if is_valid_doc_id(d):
                    filtered.append(d)

            if not filtered:
                continue

            if t not in index:
                index[t] = []

            # dedup sem perder estabilidade (bom para testes)
            existing = set(index[t])
            for d in filtered:
                if d not in existing:
                    index[t].append(d)
                    existing.add(d)
                    accepted_pairs += 1

            accepted_terms += 1

        save_index(index)

    # 2) Guardar documentos cifrados (apenas doc_ids válidos)
    accepted_docs = 0
    for doc_id, blob in docs_in.items():
        if not is_valid_doc_id(doc_id):
            continue
        if not isinstance(blob, dict):
            continue
        # (Opcional) valida campos esperados
        if "nonce" not in blob or "ciphertext" not in blob:
            continue

        path = doc_path(doc_id)
        # escrita simples; se quiseres robustez extra, também podes fazer atómica por doc
        with open(path, "w", encoding="utf-8") as f:
            json.dump(blob, f, ensure_ascii=False)
        accepted_docs += 1

    return jsonify({
        "status": "ok",
        "indexed_terms_received": len(index_in),
        "docs_received": len(docs_in),
        "accepted_terms": accepted_terms,
        "accepted_pairs": accepted_pairs,
        "accepted_docs": accepted_docs,
    })

@APP.post("/search")
def search():
    """
    Recebe:
      { "trapdoor": "hex...", "include_docs": true/false }

    Devolve (por defeito):
      { "docIds": [...], "count": n_pesquisas }

    Se include_docs=true:
      { "docIds": [...], "docs": {docId:{nonce,ciphertext}}, "count": ... }
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "error": "invalid_json"}), 400

    t = payload.get("trapdoor", "")
    include_docs = bool(payload.get("include_docs", False))

    if not is_valid_trapdoor(t):
        return jsonify({"status": "error", "error": "invalid_trapdoor"}), 400

    index = load_index()
    doc_ids = index.get(t, [])

    # Leakage stats: contar pesquisas por trapdoor (padrão de pesquisa)
    with STATS_LOCK:
        stats = load_search_stats()
        stats[t] = int(stats.get(t, 0)) + 1
        save_search_stats(stats)
        count = stats[t]

    if not include_docs:
        return jsonify({"docIds": doc_ids, "count": count})

    # Modo compatível/legado: devolver também docs cifrados
    docs_out = {}
    for doc_id in doc_ids:
        if not is_valid_doc_id(doc_id):
            continue
        path = doc_path(doc_id)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                docs_out[doc_id] = json.load(f)

    return jsonify({"docIds": doc_ids, "docs": docs_out, "count": count})

@APP.get("/doc/<doc_id>")
def get_doc(doc_id: str):
    """
    Devolve um único documento cifrado (nonce+ciphertext).
    Útil para separar pesquisa (IDs) de fetch (ciphertext).
    """
    if not is_valid_doc_id(doc_id):
        return jsonify({"status": "error", "error": "invalid_doc_id"}), 400

    path = doc_path(doc_id)
    if not os.path.exists(path):
        return jsonify({"status": "error", "error": "not_found"}), 404

    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)

    return jsonify({"docId": doc_id, "blob": blob})

# -------------------------
# Main
# -------------------------

if __name__ == "__main__":
    # Config por variáveis de ambiente (melhor para avaliação)
    # Ex.: HOST=0.0.0.0 PORT=5000 DEBUG=0 python server.py
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("DEBUG", "0").strip() in ("1", "true", "True", "yes", "YES")

    APP.run(host=host, port=port, debug=debug, threaded=True)
