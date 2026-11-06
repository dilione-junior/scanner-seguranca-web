// ---- Biblioteca: domínio, IDs para APIs e IOCs em formato seguro ----

// Segundos níveis comuns em domínios de país (com.br, co.uk...). É uma aproximação da
// Public Suffix List, suficiente para achar o domínio registrado (whois/RDAP, VirusTotal, SPF/DMARC).
const SEGUNDO_NIVEL = new Set([
  'com', 'net', 'org', 'gov', 'edu', 'mil', 'co', 'ac', 'or', 'ne', 'go', 'gob', 'nom', 'ltd', 'plc', 'sch',
  'art', 'blog', 'app', 'dev', 'eco', 'emp', 'ind', 'inf', 'adv', 'eng', 'med', 'tur', 'tv', 'arq', 'jus', 'leg', 'mp',
]);

// "www.loja.exemplo.com.br" -> "exemplo.com.br";  "a.b.exemplo.com" -> "exemplo.com"
function dominioRegistravel(host) {
  const rotulos = String(host ?? '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (rotulos.length <= 2) return rotulos.join('.');
  const tld = rotulos[rotulos.length - 1];
  const segundo = rotulos[rotulos.length - 2];
  const tamanho = tld.length === 2 && SEGUNDO_NIVEL.has(segundo) ? 3 : 2;
  return rotulos.slice(-tamanho).join('.');
}

// ID de URL do VirusTotal: base64url da URL, sem "=" no final.
// Feito à mão porque a sandbox do nó Code nem sempre tem Buffer/btoa. A URL chega canônica (só ASCII).
function base64Url(texto) {
  const tabela = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const bytes = [];
  for (const c of String(texto)) {
    const codigo = c.charCodeAt(0);
    if (codigo < 0x80) bytes.push(codigo);
    else for (const b of unescape(encodeURIComponent(c))) bytes.push(b.charCodeAt(0));
  }
  let saida = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    saida += tabela[(n >> 18) & 63] + tabela[(n >> 12) & 63];
    if (i + 1 < bytes.length) saida += tabela[(n >> 6) & 63];
    if (i + 2 < bytes.length) saida += tabela[n & 63];
  }
  return saida;
}

// IOC "desarmado" para colar em chamado, e-mail ou chat sem virar link clicável:
// https://mal.com/x -> hxxps://mal[.]com/x ;  1.2.3.4 -> 1.2.3[.]4
function desarmar(ioc) {
  const texto = String(ioc ?? '');
  const url = texto.match(/^(https?)(:\/\/)([^/?#]*)(.*)$/i);
  if (!url) return texto.replace(/\./g, '[.]');
  return url[1].replace(/tt/i, 'xx') + url[2] + url[3].replace(/\./g, '[.]') + url[4];
}

// Escapa caracteres de controle e corta textos vindos de APIs/sites antes de irem para a IA.
function textoCurto(texto, maximo = 200) {
  return String(texto ?? '').replace(/[\u0000-\u001f\u007f<>`]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, maximo);
}
// ---- fim da biblioteca ----
