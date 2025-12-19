# -*- coding:utf-8 _*-
"""
Servidor 'não confiável' para a demo de Searchable Symmetric Encryption (SSE).

Guarda:
  - documentos cifrados em storage/docs/*.json
  - índice invertido por trapdoor em storage/index.json
  - estatísticas de leakage (número de pesquisas por trapdoor) em storage/stats/search_stats.json
  - ficheiro de métricas storage/stats/metrics.csv (produzido pelo cliente)

Rotas principais:
  - GET/POST /        : vista do servidor (apenas trapdoors/docIds)
  - GET       /stats  : leakage de pesquisas (trapdoors + contagens)
  - GET       /metrics: métricas de desempenho (metrics.csv)
  - GET/POST /client  : vista do cliente (DEMO VISUAL: descifra só para mostrar no browser)
  - POST     /upload  : upload de índice e docs cifrados
  - POST     /search  : pesquisa por trapdoor
"""

import json
import os
import csv
import hashlib
from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP = Flask(__name__)

# Diretórios do projeto
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_DIR = os.path.join(PROJECT_DIR, "storage")
DOCS_DIR = os.path.join(STORAGE_DIR, "docs")
STATS_DIR = os.path.join(STORAGE_DIR, "stats")

os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(STATS_DIR, exist_ok=True)

INDEX_PATH = os.path.join(STORAGE_DIR, "index.json")
SEARCH_STATS_PATH = os.path.join(STATS_DIR, "search_stats.json")
METRICS_PATH = os.path.join(STATS_DIR, "metrics.csv")

# Chave mestra do "cliente real" (gerada em client.py)
KEY_PATH = os.path.join(PROJECT_DIR, "master.key")


# -------------------------
# Helpers índice cifrado
# -------------------------

def load_index():
    """Carrega index.json: trapdoorHex -> [docId, ...]."""
    if not os.path.exists(INDEX_PATH):
        return {}
    with open(INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_index(index):
    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)


# -------------------------
# Helpers leakage pesquisas
# -------------------------

def load_search_stats():
    """search_stats.json: trapdoorHex -> count."""
    if not os.path.exists(SEARCH_STATS_PATH):
        return {}
    with open(SEARCH_STATS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_search_stats(stats):
    with open(SEARCH_STATS_PATH, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)


# -------------------------
# Helpers "cliente" (DEMO VISUAL)
# -------------------------

def load_master_key() -> bytes:
    """Lê master.key se existir (gerado pelo client.py)."""
    if not os.path.exists(KEY_PATH):
        return b""
    with open(KEY_PATH, "rb") as f:
        return f.read()

def derive_keys(master_key: bytes):
    """
    Derivação compatível com client.py:
      - K_trap: trapdoors (não usado aqui)
      - K_enc : cifragem/descifra (AES-GCM)
    """
    k_trap = hashlib.sha256(master_key + b"trap").digest()
    k_enc = hashlib.sha256(master_key + b"enc").digest()
    return k_trap, k_enc

def decrypt_doc(k_enc: bytes, blob: dict) -> str:
    """Descifra blob {nonce,ciphertext} usando AES-GCM."""
    aesgcm = AESGCM(k_enc)
    nonce = bytes.fromhex(blob["nonce"])
    ct = bytes.fromhex(blob["ciphertext"])
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt.decode("utf-8")


# -------------------------
# Vistas HTML
# -------------------------

@APP.route("/", methods=["GET", "POST"])
def home():
    """
    Vista do servidor:
      - se receber um docId (emp_001) mostra só se existe
      - se receber um trapdoor, mostra apenas docIds associados
    """
    term = ""
    results = []

    if request.method == "POST":
        term = request.form.get("term", "").strip()
        index = load_index()

        if term.startswith("emp_"):
            path = os.path.join(DOCS_DIR, f"{term}.json")
            if os.path.exists(path):
                results = [term]
        else:
            results = index.get(term, [])

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
    Vista do cliente (APENAS PARA DEMO VISUAL):
      - recebe trapdoor (hex)
      - usa o índice local para obter docIds
      - lê blobs cifrados do storage
      - descifra para mostrar no browser

    Nota importante:
      - Isto NÃO é o "cliente real" do modelo de ameaça.
      - O cliente real é o script client.py (onde a chave deve residir).
      - Esta vista existe para visualização e demonstração rápida.
    """
    term = ""
    docs = {}  # docId -> plaintext

    if request.method == "POST":
        term = request.form.get("term", "").strip()

        # 1) Lookup de docIds
        index = load_index()
        doc_ids = index.get(term, [])

        # 2) Ler blobs cifrados
        blobs = {}
        for doc_id in doc_ids:
            path = os.path.join(DOCS_DIR, f"{doc_id}.json")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    blobs[doc_id] = json.load(f)

        # 3) Leakage (contar pesquisas)
        stats = load_search_stats()
        stats[term] = stats.get(term, 0) + 1
        save_search_stats(stats)

        # 4) Descifrar (DEMO VISUAL)
        master = load_master_key()
        if master:
            _, k_enc = derive_keys(master)
            for doc_id, blob in blobs.items():
                try:
                    docs[doc_id] = decrypt_doc(k_enc, blob)
                except Exception:
                    # Se falhar a descifra, não quebrar a página
                    pass

    return render_template("client.html", term=term, docs=docs)


# -------------------------
# API JSON
# -------------------------

@APP.get("/health")
def health():
    return jsonify({"status": "ok"})

@APP.get("/doc/<doc_id>")
def get_doc(doc_id: str):
    """
    Endpoint usado pelo client.py para medir tempos separados (fetch por docId).

    Devolve:
      { "docId": "<id>", "blob": { "nonce": "...", "ciphertext": "..." } }

    Se não existir:
      404 { "error": "doc_not_found", "docId": "<id>" }
    """
    doc_id = (doc_id or "").replace(".json", "").strip()

    # Defesa contra paths manhosos: só permite nomes simples
    if "/" in doc_id or "\\" in doc_id or ".." in doc_id:
        return jsonify({"error": "invalid_doc_id", "docId": doc_id}), 400

    path = os.path.join(DOCS_DIR, f"{doc_id}.json")
    if not os.path.exists(path):
        return jsonify({"error": "doc_not_found", "docId": doc_id}), 404

    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)

    return jsonify({"docId": doc_id, "blob": blob})


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
    payload = request.get_json(force=True)

    index_in = payload.get("index", {})
    docs_in = payload.get("docs", {})

    # 1) Merge do índice
    index = load_index()
    for t, doc_ids in index_in.items():
        if t not in index:
            index[t] = []
        for d in doc_ids:
            if d not in index[t]:
                index[t].append(d)
    save_index(index)

    # 2) Guardar documentos cifrados
    for doc_id, blob in docs_in.items():
        path = os.path.join(DOCS_DIR, f"{doc_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(blob, f, ensure_ascii=False)

    return jsonify({
        "status": "ok",
        "indexed_terms_received": len(index_in),
        "docs_received": len(docs_in),
    })


@APP.post("/search")
def search():
    """
    Recebe:
      { "trapdoor": "hex..." }

    Devolve:
      {
        "docIds": [docId, ...],
        "docs":  { docId: {nonce,ciphertext}, ... },
        "count": nº de vezes que este trapdoor foi pesquisado
      }
    """
    payload = request.get_json(force=True)
    t = payload.get("trapdoor")

    index = load_index()
    doc_ids = index.get(t, [])

    docs_out = {}
    for doc_id in doc_ids:
        path = os.path.join(DOCS_DIR, f"{doc_id}.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                docs_out[doc_id] = json.load(f)

    stats = load_search_stats()
    stats[t] = stats.get(t, 0) + 1
    save_search_stats(stats)

    return jsonify({
        "docIds": doc_ids,
        "docs": docs_out,
        "count": stats[t],
    })


if __name__ == "__main__":
    APP.run(host="127.0.0.1", port=5000, debug=True)
