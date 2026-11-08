// ---- Biblioteca: páginas de registro de bases de ameaças ----
// Quem copia um link "do URLhaus" às vezes copia o endereço da PÁGINA do registro
// (ex.: https://urlhaus.abuse.ch/url/4060974/), e não a URL maliciosa listada nela.
// Analisar essa página daria "limpo": o site do URLhaus é legítimo. Esta função reconhece
// essas páginas para o fluxo trocar pelo indicador verdadeiro (URLhaus) ou pedir a URL certa.
const PAGINAS_DE_REGISTRO = [
  { host: 'urlhaus.abuse.ch', caminho: /^\/url\/(\d+)\/?$/, plataforma: 'URLhaus' },
  { host: 'urlhaus.abuse.ch', caminho: /^\/host\/[^/]+\/?$/, plataforma: 'URLhaus' },
  { host: 'threatfox.abuse.ch', caminho: /^\/ioc\/\d+\/?$/, plataforma: 'ThreatFox' },
  { host: 'bazaar.abuse.ch', caminho: /^\/sample\/[0-9a-f]+\/?$/i, plataforma: 'MalwareBazaar' },
  { host: 'www.virustotal.com', caminho: /^\/gui\/(url|domain|ip-address|file)\//, plataforma: 'VirusTotal' },
  { host: 'virustotal.com', caminho: /^\/gui\/(url|domain|ip-address|file)\//, plataforma: 'VirusTotal' },
  { host: 'urlscan.io', caminho: /^\/result\/[0-9a-f-]+\/?/i, plataforma: 'urlscan.io' },
  { host: 'otx.alienvault.com', caminho: /^\/indicator\//, plataforma: 'OTX' },
  { host: 'www.abuseipdb.com', caminho: /^\/check\//, plataforma: 'AbuseIPDB' },
];

// Recebe a URL canônica (de analisarUrl) e devolve { plataforma, idUrlhaus } ou null.
function paginaDeRegistro(href) {
  const m = String(href ?? '').match(/^https?:\/\/([^/:?#]+)(?::\d+)?(\/[^?#]*)?/i);
  if (!m) return null;
  const host = m[1].toLowerCase();
  const caminho = m[2] || '/';
  for (const p of PAGINAS_DE_REGISTRO) {
    if (p.host !== host) continue;
    const c = caminho.match(p.caminho);
    if (c) return { plataforma: p.plataforma, idUrlhaus: p.plataforma === 'URLhaus' && /^\d+$/.test(c[1] ?? '') ? c[1] : '' };
  }
  return null;
}
// ---- fim da biblioteca ----
