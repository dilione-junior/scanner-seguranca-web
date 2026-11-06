#!/usr/bin/env bash
# Cria no n8n as credenciais do scanner a partir de um arquivo .env. As chaves nunca são impressas
# nem ficam salvas fora do n8n (que guarda criptografado).
#
#   GEMINI_API_KEY      -> "Google Gemini (scanner)"
#   VIRUSTOTAL_API_KEY  -> "VirusTotal (x-apikey)"
#   ABUSECH_AUTH_KEY    -> "abuse.ch (Auth-Key)"      (URLhaus e ThreatFox)
#   OTX_API_KEY         -> "OTX (X-OTX-API-KEY)"
#   ABUSEIPDB_API_KEY   -> "AbuseIPDB (Key)"
#   URLSCAN_API_KEY     -> "urlscan.io (API-Key)"
#
# Só cria as credenciais cujas chaves estão preenchidas. Se já existir no n8n uma credencial com o
# mesmo nome (por exemplo, criada pela tela ou por outro projeto), ela é mantida e não é duplicada.
#
# Antes: copie .env.exemplo para .env e cole as chaves (no Bloco de Notas, nunca num chat).
# Uso:   bash scripts/importar-credenciais.sh [nome-do-container] [arquivo-env]
#        (padrões: ng-soc-automacao-n8n-1 e .env)
#
# O Outlook usa OAuth (login no navegador), então é configurado pela tela do n8n; veja o README.
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
export PYTHONIOENCODING=utf-8

n8n="${1:-ng-soc-automacao-n8n-1}"
env_arquivo="${2:-.env}"
[ -f "$env_arquivo" ] || { echo "Arquivo $env_arquivo não encontrado. Copie .env.exemplo para .env e cole as chaves."; exit 1; }

existentes=$(docker exec "$n8n" sh -c 'umask 077; n8n export:credentials --all --output=/tmp/cred-lista.json >/dev/null 2>&1; cat /tmp/cred-lista.json; rm -f /tmp/cred-lista.json' \
    | python -c "import json,sys; print(json.dumps([c['name'] for c in json.load(sys.stdin)]))")

saida=$(python - "$env_arquivo" "$existentes" <<'PY'
import json, sys
valores = {}
with open(sys.argv[1], encoding="utf-8") as f:
    for linha in f:
        linha = linha.strip()
        if linha and not linha.startswith("#") and "=" in linha:
            k, v = linha.split("=", 1)
            valores[k.strip()] = v.strip().strip('"').strip("'")
existentes = set(json.loads(sys.argv[2]))

def chave(nome):
    v = valores.get(nome, "")
    return "" if not v or v.startswith("cole-") else v

def cabecalho(id_, nome, cabecalho_http, variavel):
    return {"id": id_, "name": nome, "type": "httpHeaderAuth",
            "data": {"name": cabecalho_http, "value": chave(variavel)}, "_var": variavel}

candidatas = [
    {"id": "scanGeminiApi001", "name": "Google Gemini (scanner)", "type": "googlePalmApi",
     "data": {"host": "https://generativelanguage.googleapis.com", "apiKey": chave("GEMINI_API_KEY")}, "_var": "GEMINI_API_KEY"},
    cabecalho("scanVirusTotal01", "VirusTotal (x-apikey)", "x-apikey", "VIRUSTOTAL_API_KEY"),
    cabecalho("scanAbusechKey01", "abuse.ch (Auth-Key)", "Auth-Key", "ABUSECH_AUTH_KEY"),
    cabecalho("scanOtxApiKey001", "OTX (X-OTX-API-KEY)", "X-OTX-API-KEY", "OTX_API_KEY"),
    cabecalho("scanAbuseipdb001", "AbuseIPDB (Key)", "Key", "ABUSEIPDB_API_KEY"),
    cabecalho("scanUrlscanKey01", "urlscan.io (API-Key)", "API-Key", "URLSCAN_API_KEY"),
]
criar = []
for c in candidatas:
    var = c.pop("_var")
    if not chave(var):
        print(f"  {c['name']}: {var} vazia no .env, pulando", file=sys.stderr)
    elif c["name"] in existentes:
        print(f"  {c['name']}: já existe no n8n, mantida", file=sys.stderr)
    else:
        print(f"  {c['name']}: será criada", file=sys.stderr)
        criar.append(c)
print(json.dumps(criar))
PY
)

if [ "$saida" = "[]" ]; then
    echo "Nenhuma credencial nova para criar."
    exit 0
fi
printf '%s' "$saida" | docker exec -i "$n8n" sh -c '
    umask 077
    cat > /tmp/cred-scanner.json
    n8n import:credentials --input=/tmp/cred-scanner.json >/dev/null 2>&1; status=$?
    rm -f /tmp/cred-scanner.json
    exit $status'
echo "Credenciais criadas no n8n."
