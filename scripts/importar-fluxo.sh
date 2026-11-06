#!/usr/bin/env bash
# Importa e publica o fluxo no n8n que roda em Docker.
# Atenção: substitui a versão do fluxo que estiver no n8n com o mesmo id (scannerSegWeb001).
# Se alterou o fluxo pela tela do n8n, exporte-o antes ou as mudanças serão perdidas.
#
# Uso:  bash scripts/importar-fluxo.sh [nome-do-container]   (padrão: ng-soc-automacao-n8n-1)
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1   # Git Bash no Windows: não converter caminhos como /tmp

n8n="${1:-ng-soc-automacao-n8n-1}"
id=scannerSegWeb001

python scripts/gerar-fluxo.py
docker cp workflow/scanner-seguranca-web.json "$n8n":/tmp/scanner.json
docker exec "$n8n" n8n import:workflow --input=/tmp/scanner.json
docker exec -u root "$n8n" rm -f /tmp/scanner.json
docker exec "$n8n" n8n publish:workflow --id="$id"
docker restart "$n8n" >/dev/null
echo "n8n reiniciado. Aguardando o formulário responder..."

for _ in $(seq 1 60); do
    codigo=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5678/form/scanner-seguranca-web || true)
    if [ "$codigo" = "200" ]; then
        echo "Pronto: http://127.0.0.1:5678/form/scanner-seguranca-web"
        exit 0
    fi
    sleep 2
done
echo "O formulário não respondeu em 2 minutos. Veja: docker logs $n8n"
exit 1
