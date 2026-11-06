// Nó "Tratar resposta": decide se segue um redirecionamento ou se parte para a análise.
// O nó "Buscar site" NÃO segue redirecionamentos sozinho: cada novo endereço volta para
// "Validar URL" e "Verificar DNS" antes de ser acessado (no máximo 5 vezes).
const MAX_REDIRECIONAMENTOS = 5;
const alvo = $('Verificar DNS').last().json;
const config = $('Configuração').first().json;
const resposta = $input.first().json;

const status = Number(resposta.statusCode ?? 0);
const cabecalhos = {};
for (const [nome, valor] of Object.entries(resposta.headers ?? {})) {
  cabecalhos[nome.toLowerCase()] = valor;
}
const cadeia = [...(alvo.cadeia ?? []), { url: alvo.url, status }];

const local = Array.isArray(cabecalhos.location) ? cabecalhos.location[0] : cabecalhos.location;
const ehRedirecionamento = [301, 302, 303, 307, 308].includes(status) && local;

if (ehRedirecionamento && alvo.saltos < MAX_REDIRECIONAMENTOS) {
  const proxima = resolverUrl(local, alvo.url);
  if (proxima) {
    return [{
      json: {
        acao: 'redirecionar',
        url: proxima,
        urlOriginal: alvo.urlOriginal,
        saltos: alvo.saltos + 1,
        cadeia,
      },
    }];
  }
}

// Texto da página, sem imagens embutidas em base64 (gastam tokens e não ajudam a análise).
let conteudo = typeof resposta.data === 'string' ? resposta.data
  : typeof resposta.body === 'string' ? resposta.body
  : JSON.stringify(resposta.data ?? resposta.body ?? '');
const tamanhoConteudo = conteudo.length;
conteudo = conteudo.replace(/data:[a-z0-9.+\/-]+;base64,[a-z0-9+\/=\s]{200,}/gi, 'data:[base64 removido]');
const limite = Number(config.limiteConteudo) || 60000;
const conteudoTruncado = conteudo.length > limite;
if (conteudoTruncado) conteudo = conteudo.slice(0, limite);

const cabecalhosFormatados = Object.entries(cabecalhos)
  .flatMap(([nome, valor]) => (Array.isArray(valor) ? valor : [valor]).map((v) => `${nome}: ${v}`))
  .join('\n');

return [{
  json: {
    acao: 'analisar',
    urlOriginal: alvo.urlOriginal,
    urlFinal: alvo.url,
    host: alvo.host,
    ips: alvo.ips,
    status,
    statusMessage: resposta.statusMessage ?? '',
    cabecalhos,
    cabecalhosFormatados,
    conteudo,
    conteudoTruncado,
    tamanhoConteudo,
    cadeia,
    parouNoLimite: Boolean(ehRedirecionamento),
  },
}];
