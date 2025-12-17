# -*- coding:utf-8 _*-
"""
Cliente de demonstração para pesquisa sobre dados cifrados (Searchable Symmetric Encryption)
aplicado a um dataset de Recursos Humanos em CSV (employee_salary_dataset*.csv).

Gera também um ficheiro storage/stats/metrics.csv com colunas:
Termo, Nº funcionários, Nº docs retornados, Tempo pesquisa (s), Tempo build (s), Tempo upload (s)

Comandos:
  python client.py build-and-upload docs/employee_salary_dataset.csv
  python client.py search "Marketing"
  python client.py search-plain docs/employee_salary_dataset.csv "Marketing"
"""

import os
import re
import json
import hmac
import csv
import hashlib
import secrets
import time
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------
# Configuração básica
# -------------------------

SERVER = "http://127.0.0.1:5000"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

KEY_PATH = os.path.join(PROJECT_DIR, "master.key")

STORAGE_DIR = os.path.join(PROJECT_DIR, "storage")
STATS_DIR = os.path.join(STORAGE_DIR, "stats")
os.makedirs(STATS_DIR, exist_ok=True)
METRICS_CSV = os.path.join(STATS_DIR, "metrics.csv")


# -------------------------
# 1) Setup: chaves
# -------------------------

def load_or_create_master_key() -> bytes:
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()

    key = secrets.token_bytes(32)  # 256-bit
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key


def derive_keys(master_key: bytes):
    """
    Derivação simples:
      - K_trap: geração de trapdoors (HMAC)
      - K_enc : cifragem de documentos (AES-GCM)
    """
    k_trap = hashlib.sha256(master_key + b"trap").digest()
    k_enc = hashlib.sha256(master_key + b"enc").digest()
    return k_trap, k_enc


# -------------------------
# 2) Trapdoor: HMAC-SHA256
# -------------------------

def trapdoor(k_trap: bytes, keyword: str) -> str:
    return hmac.new(k_trap, keyword.encode("utf-8"), hashlib.sha256).hexdigest()


# -------------------------
# 3) Normalização e extração de keywords
# -------------------------

def normalize(text: str) -> str:
    return text.strip().lower()


def extract_keywords(text: str):
    text_norm = normalize(text)
    tokens = re.sub(r"[^\w\s]+", " ", text_norm).split()
    kws = sorted(set(t for t in tokens if len(t) >= 3))
    return kws


# -------------------------
# 4) Cifra: AES-256-GCM
# -------------------------

def encrypt_doc(k_enc: bytes, plaintext: str):
    aesgcm = AESGCM(k_enc)
    nonce = secrets.token_bytes(12)  # 96-bit nonce recomendado
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return {"nonce": nonce.hex(), "ciphertext": ct.hex()}


def decrypt_doc(k_enc: bytes, blob):
    aesgcm = AESGCM(k_enc)
    nonce = bytes.fromhex(blob["nonce"])
    ct = bytes.fromhex(blob["ciphertext"])
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt.decode("utf-8")


# -------------------------
# 5) Build a partir do CSV de RH (com salário no texto cifrado)
# -------------------------

def build_dataset_from_hr_csv(csv_path: str):
    """
    Constrói:
      - index: trapdoorHex -> [docId]
      - enc_docs: docId -> {nonce,ciphertext}
      - total_docs: nº de funcionários

    O texto cifrado inclui o salário (para mostrar proteção de dados sensíveis com SSE).
    """
    if not os.path.exists(csv_path):
        raise RuntimeError(f"CSV de RH não encontrado: {csv_path}")

    master = load_or_create_master_key()
    k_trap, k_enc = derive_keys(master)

    index = {}      # trapdoorHex -> [docId]
    enc_docs = {}   # docId -> {nonce,ciphertext}
    total_docs = 0

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            emp_id = row["EmployeeID"]
            dept = row["Department"]
            city = row["City"]
            edu = row["Education_Level"]
            gender = row["Gender"]
            salary = row["Monthly_Salary"]

            doc_id = f"emp_{int(emp_id):03d}"
            total_docs += 1

            content = (
                f"Funcionario {doc_id} trabalha no departamento {dept} "
                f"na cidade de {city}, com escolaridade {edu}, "
                f"genero {gender} e salario mensal {salary}."
            )

            enc_docs[doc_id] = encrypt_doc(k_enc, content)

            kws = extract_keywords(content)
            for w in kws:
                t = trapdoor(k_trap, normalize(w))
                index.setdefault(t, [])
                if doc_id not in index[t]:
                    index[t].append(doc_id)

    return k_trap, k_enc, index, enc_docs, total_docs


# -------------------------
# 6) Upload para o servidor
# -------------------------

def upload(index, enc_docs):
    r = requests.post(
        f"{SERVER}/upload",
        json={"index": index, "docs": enc_docs},
        timeout=30
    )
    r.raise_for_status()
    return r.json()


# -------------------------
# 7) Pesquisa cifrada: envia trapdoor, recebe cifrados, decifra localmente
# -------------------------

def search_and_decrypt(query: str):
    """
    Pesquisa por palavra‑chave (ex.: "Marketing") com SSE:
      - gera trapdoor com HMAC
      - envia ao servidor
      - recebe docs cifrados
      - descifra localmente
    """
    master = load_or_create_master_key()
    k_trap, k_enc = derive_keys(master)

    q = normalize(query)
    t = trapdoor(k_trap, q)

    r = requests.post(
        f"{SERVER}/search",
        json={"trapdoor": t},
        timeout=30
    )
    r.raise_for_status()
    data = r.json()

    docs = data.get("docs", {})
    results = {}
    for doc_id, blob in docs.items():
        results[doc_id] = decrypt_doc(k_enc, blob)

    return {
        "trapdoor": t,
        "docIds": data.get("docIds", []),
        "plaintext": results,
        "count": data.get("count", None),
    }


# -------------------------
# 8) Pesquisa em claro (para comparação de desempenho)
# -------------------------

def plaintext_search(csv_path: str, term: str):
    """
    Pesquisa em claro diretamente no CSV, sem cifragem nem SSE.
    Apenas para comparação de desempenho com o cenário cifrado.
    """
    if not os.path.exists(csv_path):
        raise RuntimeError(f"CSV de RH não encontrado: {csv_path}")

    term_norm = normalize(term)
    results = []

    start = time.time()
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            emp_id = row["EmployeeID"]
            dept = row["Department"]
            city = row["City"]
            edu = row["Education_Level"]
            gender = row["Gender"]
            salary = row["Monthly_Salary"]

            content = (
                f"Funcionario emp_{int(emp_id):03d} trabalha no departamento {dept} "
                f"na cidade de {city}, com escolaridade {edu}, "
                f"genero {gender} e salario mensal {salary}."
            )

            if term_norm in normalize(content):
                results.append(content)

    search_time = time.time() - start
    return results, search_time


# -------------------------
# 9) CSV de métricas (para gráficos no Excel)
# -------------------------

def append_metrics(row: dict):
    """
    Acrescenta uma linha ao ficheiro storage/stats/metrics.csv com colunas:
    Termo, Nº funcionários, Nº docs retornados,
    Tempo pesquisa (s), Tempo build (s), Tempo upload (s)
    """
    file_exists = os.path.exists(METRICS_CSV)
    with open(METRICS_CSV, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Termo",
                "Nº funcionários",
                "Nº docs retornados",
                "Tempo pesquisa (s)",
                "Tempo build (s)",
                "Tempo upload (s)",
            ],
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


# -------------------------
# CLI simples
# -------------------------

if __name__ == "__main__":
    import sys

    prog = os.path.basename(__file__)

    if len(sys.argv) < 2:
        print("Uso:")
        print(f"  python {prog} build-and-upload <ficheiro_csv_relativo_à_raiz>")
        print(f'  python {prog} search "termo"')
        print(f'  python {prog} search-plain <ficheiro_csv_relativo_à_raiz> "termo"')
        raise SystemExit(1)

    cmd = sys.argv[1]

    if cmd == "build-and-upload":
        if len(sys.argv) < 3:
            raise SystemExit(
                f'Falta CSV. Ex.: python {prog} build-and-upload docs/employee_salary_dataset.csv'
            )

        csv_rel = sys.argv[2]
        csv_path = os.path.join(PROJECT_DIR, csv_rel)

        start_build = time.time()
        _, _, index, enc_docs, total_docs = build_dataset_from_hr_csv(csv_path)
        build_time = time.time() - start_build

        start_upload = time.time()
        resp = upload(index, enc_docs)
        upload_time = time.time() - start_upload

        print("UPLOAD:", json.dumps(resp, indent=2))
        print(f"\nTempo build (cifrar + indexar): {build_time:.3f}s")
        print(f"Tempo upload: {upload_time:.3f}s")

        # linha de métricas para este build
        append_metrics({
            "Termo": "",
            "Nº funcionários": total_docs,
            "Nº docs retornados": "",
            "Tempo pesquisa (s)": "",
            "Tempo build (s)": f"{build_time:.3f}",
            "Tempo upload (s)": f"{upload_time:.3f}",
        })

    elif cmd == "search":
        if len(sys.argv) < 3:
            raise SystemExit(
                f'Falta termo. Ex.: python {prog} search "Marketing"'
            )
        term = sys.argv[2]

        start_search = time.time()
        out = search_and_decrypt(term)
        search_time = time.time() - start_search

        print("TRAPDOOR (enviado ao servidor):", out["trapdoor"])
        print("DOC IDs:", out["docIds"])
        if out.get("count") is not None:
            print(f"Este trapdoor já foi pesquisado {out['count']} vezes (leakage de padrão).")
        print(f"Tempo de pesquisa (cliente+servidor): {search_time:.3f}s")

        print("\nRESULTADOS (decifrados no cliente):")
        for doc_id, text in out["plaintext"].items():
            print("\n---", doc_id, "---\n", text)

        docs_returned = len(out["docIds"])

        append_metrics({
            "Termo": term,
            "Nº funcionários": "",
            "Nº docs retornados": docs_returned,
            "Tempo pesquisa (s)": f"{search_time:.3f}",
            "Tempo build (s)": "",
            "Tempo upload (s)": "",
        })

    elif cmd == "search-plain":
        if len(sys.argv) < 4:
            raise SystemExit(
                f'Uso: python {prog} search-plain <ficheiro_csv_relativo_à_raiz> "termo"'
            )
        csv_rel = sys.argv[2]
        term = sys.argv[3]
        csv_path = os.path.join(PROJECT_DIR, csv_rel)

        results, t_plain = plaintext_search(csv_path, term)
        print(f"Pesquisa em claro, termo '{term}': {len(results)} resultados, tempo = {t_plain:.3f}s")
        for r in results[:5]:
            print("\n--- RESULTADO ---\n", r)

        # registo de métricas para pesquisa em claro (podes preencher Nº funcionários depois no Excel)
        append_metrics({
            "Termo": f"{term} (plain)",
            "Nº funcionários": "",
            "Nº docs retornados": len(results),
            "Tempo pesquisa (s)": f"{t_plain:.3f}",
            "Tempo build (s)": "",
            "Tempo upload (s)": "",
        })

    else:
        raise SystemExit(f"Comando desconhecido: {cmd}")
