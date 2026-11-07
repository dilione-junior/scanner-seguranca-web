// Nó "Link relacionado": quando o endereço passa por outro domínio (encurtador, rastreador,
// cadeia de phishing), descobre a OUTRA ponta da cadeia para consultar a reputação dela também.
//  - Modo completo: o scanner seguiu os redirecionamentos e as fontes viram o destino final.
//    A outra ponta é o link ORIGINAL (ex.: bit.ly/abc), que até agora não era consultado.
//  - Modo só reputação: o site não é acessado (nem o encurtador: abrir o link curto conta um
//    clique que o autor do link vê). A outra ponta é o DESTINO que o VirusTotal já conhece
//    (campo last_final_url da última análise da URL).
// Nada é visitado aqui: a URL relacionada só é CONSULTADA no VirusTotal e no URLhaus.
const alvo = $('Preparar consultas').first().json;
const host = String(alvo.host ?? '').toLowerCase();
const dominio = String(alvo.dominio ?? '');

function hostDe(url) {
  try { return analisarUrl(url).host; } catch (erro) { return ''; }
}
const outroDominio = (h) => Boolean(h) && h !== host && dominioRegistravel(h) !== dominio;

let papel = '';
let url = '';
let destinoDesconhecido = false;

if (alvo.visitado) {
  const hOriginal = hostDe(alvo.urlOriginal);
  if (alvo.urlOriginal && alvo.urlOriginal !== alvo.urlFinal && outroDominio(hOriginal)) {
    papel = 'origem';
    url = alvo.urlOriginal;
  }
} else {
  let at = null;
  try {
    const r = $('VirusTotal (URL)').first().json;
    const corpo = typeof r.body === 'string' ? JSON.parse(r.body) : r.body;
    at = corpo?.data?.attributes ?? null;
  } catch (erro) { /* VirusTotal não respondeu */ }
  const final = String(at?.last_final_url ?? '').trim();
  let finalCanonica = '';
  try { finalCanonica = final ? analisarUrl(final).href : ''; } catch (erro) { /* URL estranha: ignora */ }
  if (finalCanonica && outroDominio(hostDe(finalCanonica))) {
    papel = 'destino';
    url = finalCanonica;
  } else if (ehEncurtador(host)) {
    // Link encurtado e o VirusTotal não sabe para onde ele leva.
    destinoDesconhecido = true;
  }
}

const hostRelacionado = url ? hostDe(url) : '';
return [{
  json: {
    consultar: Boolean(url),
    papel,
    url,
    host: hostRelacionado,
    vtUrlId: url ? base64Url(url) : '',
    // Encurtador: o próprio alvo (só reputação) ou o link original (modo completo).
    encurtador: ehEncurtador(host) ? host : ehEncurtador(hostRelacionado) && papel === 'origem' ? hostRelacionado : '',
    destinoDesconhecido,
  },
}];
