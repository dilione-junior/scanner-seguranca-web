// Nó "Sem visita": modo "só reputação". O scanner NÃO acessa o site (nem o Mozilla Observatory),
// para não alertar quem controla um domínio suspeito e não expor o IP do laboratório.
// Monta os mesmos campos que "Tratar resposta" entregaria, só que sem cabeçalhos e sem conteúdo.
const alvo = $input.first().json;

return [{
  json: {
    acao: 'analisar',
    urlOriginal: alvo.urlOriginal,
    urlFinal: alvo.url,
    host: alvo.host,
    ips: alvo.ips ?? [],
    status: null,
    statusMessage: '',
    cabecalhos: {},
    cabecalhosFormatados: '',
    conteudo: '',
    conteudoTruncado: false,
    tamanhoConteudo: 0,
    cadeia: [],
    parouNoLimite: false,
    visitado: false,
    dnssec: Boolean(alvo.dnssec),
    avisoDns: alvo.avisoDns ?? '',
  },
}];
