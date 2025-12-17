# RH‑SecureSearch – Protótipo de Searchable Symmetric Encryption

Protótipo académico de um sistema de pesquisa por palavra‑chave sobre dados cifrados, baseado em Searchable Symmetric Encryption (SSE), aplicado a um dataset de Recursos Humanos com salários mensais. O objetivo é demonstrar como um servidor não confiável consegue processar pesquisas sem acesso aos dados pessoais em claro, alinhado com os princípios do RGPD. [file:207]

## Arquitetura em alto nível

O sistema segue um modelo **cliente–servidor**:

- **Cliente (aplicação de RH)**  
  - Script `client.py`.  
  - Gera e guarda localmente uma `master.key`.  
  - Lê o ficheiro CSV com dados de funcionários (inclui salários).  
  - Cifra os registos com AES‑GCM e constrói um índice invertido SSE:  
    - extrai keywords dos textos (ex.: “Marketing”, “Bangalore”)  
    - gera trapdoors com HMAC‑SHA256 (`keyword → trapdoor`)  
    - associa `trapdoor → lista de docIds`.  
  - Envia para o servidor apenas:  
    - índice `trapdoor → [docIds]`  
    - documentos cifrados `docId → {nonce, ciphertext}`.  
  - Nas pesquisas:
    - gera o trapdoor da keyword (ex.: “Marketing”)  
    - envia só o trapdoor para o servidor  
    - recebe documentos cifrados correspondentes  
    - descifra localmente e mostra o texto completo ao utilizador (incluindo salários). [file:207]

- **Servidor (não confiável)**  
  - Aplicação Flask (`app.py`).  
  - Não tem acesso à `master.key`.  
  - Armazena apenas:
    - `storage/docs/*.json` – documentos cifrados  
    - `storage/index.json` – índice `trapdoor → [docIds]`  
    - `storage/stats/search_stats.json` – nº de pesquisas por trapdoor (leakage)  
    - `storage/stats/metrics.csv` – tempos de build, upload e pesquisa.  
  - Endpoints principais:
    - `POST /upload` – recebe índice e documentos cifrados do cliente  
    - `POST /search` – recebe um trapdoor e devolve docIds + blobs cifrados  
    - `GET /` – vista do servidor (mostra apenas o que o servidor sabe)  
    - `GET /stats` – leakage de pesquisas (trapdoors e contagens)  
    - `GET /metrics` – métricas de desempenho. [file:207]

Este desenho separa claramente a **aplicação com chave** (cliente) da **infraestrutura não confiável** (servidor), reduzindo o risco de exposição de dados pessoais e cumprindo princípios de minimização, integridade e confidencialidade. [file:207]

## Requisitos

- Python 3.10+  
- Bibliotecas Python:
  - `flask`
  - `requests`
  - `cryptography`

Sugestão de `requirements.txt`:


