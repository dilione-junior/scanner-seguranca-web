#!/usr/bin/env bash
# Cria (ou atualiza) no n8n a credencial "Google Gemini (scanner)" lendo GEMINI_API_KEY do arquivo .env.
# A chave nunca é impressa nem fica salva fora do n8n (que guarda criptografado).
#
# Antes: copie .env.exemplo para .env e cole a sua chave (https://aistudio.google.com/apikey).
# Uso:   bash scripts/importar-credenciais.sh [nome-do-container]   (padrão: ng-soc-automacao-n8n-1)
#
# O Gmail usa OAuth (login no navegador), então é configurado pela tela do n8n; veja o README.
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1

n8n="${1:-ng-soc-automacao-n8n-1}"
[ -f .env ] || { echo "Arquivo .env não encontrado. Copie .env.exemplo para .env e cole a chave."; exit 1; }

python - .env <<'PY' | docker exec -i "$n8n" sh -c '
    umask 077
    cat > /tmp/cred-scanner.json
    n8n import:credentials --input=/tmp/cred-scanner.json >/dev/null 2>&1; status=$?
    rm -f /tmp/cred-scanner.json
    exit $status'
import json, sys
valores = {}
with open(sys.argv[1], encoding="utf-8") as f:
    for linha in f:
        linha = linha.strip()
        if linha and not linha.startswith("#") and "=" in linha:
            k, v = linha.split("=", 1)
            valores[k.strip()] = v.strip().strip('"').strip("'")
chave = valores.get("GEMINI_API_KEY", "")
if not chave or chave.startswith("cole-"):
    sys.exit("GEMINI_API_KEY vazia no .env")
print(json.dumps([{
    "id": "scanGeminiApi001",
    "name": "Google Gemini (scanner)",
    "type": "googlePalmApi",
    "data": {"host": "https://generativelanguage.googleapis.com", "apiKey": chave},
}]))
PY
echo "Credencial 'Google Gemini (scanner)' criada/atualizada no n8n."
