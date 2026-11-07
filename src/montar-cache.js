// Nó "Montar cache": guarda no Redis as respostas das fontes de reputação desta análise,
// já enxutas (sem o que o relatório não usa), para a próxima análise da mesma URL não gastar cota.
// Fica 24 h (configurável); se alguma fonte falhou, só 1 h, para tentar de novo logo.
const VERSAO = 2; // 2: inclui o link relacionado (encurtadores)
const FONTES = [
  'urlscan (busca)', 'urlscan (enviar análise)', 'urlscan (resultado)', 'urlscan (última análise)',
  'VirusTotal (URL)', 'VirusTotal (domínio)', 'URLhaus', 'ThreatFox', 'OTX', 'AbuseIPDB',
  'Shodan InternetDB', 'RDAP (registro do domínio)', 'DNS (SPF)', 'DNS (DMARC)',
  'VirusTotal (link relacionado)', 'URLhaus (link relacionado)',
];
const alvo = $('Preparar consultas').first().json;
const config = $('Configuração').first().json;
const intel = $('Consolidar inteligência').first().json.auditoria.inteligencia;

function enxugar(nome, body) {
  if (!body || typeof body !== 'object') return body;
  const c = JSON.parse(JSON.stringify(body));
  if (nome.startsWith('VirusTotal') && c.data?.attributes) {
    const at = c.data.attributes;
    for (const campo of ['whois', 'rdap', 'last_dns_records', 'jarm', 'tags', 'total_votes', 'html_meta', 'trackers', 'outgoing_links', 'redirection_chain']) delete at[campo];
    at.last_analysis_results = Object.fromEntries(Object.entries(at.last_analysis_results ?? {})
      .filter(([, v]) => v?.category === 'malicious' || v?.category === 'suspicious'));
    if (at.last_https_certificate) at.last_https_certificate = { validity: at.last_https_certificate.validity, issuer: at.last_https_certificate.issuer };
  }
  if (nome === 'urlscan (resultado)' || nome === 'urlscan (última análise)') {
    delete c.data;
    delete c.meta;
    if (c.lists) c.lists = { domains: c.lists.domains, ips: c.lists.ips, countries: c.lists.countries };
  }
  if (nome === 'urlscan (busca)' && Array.isArray(c.results)) {
    c.results = c.results.map((r) => ({ _id: r._id, task: { time: r.task?.time, tags: r.task?.tags, url: r.task?.url }, page: { url: r.page?.url } }));
  }
  if (nome === 'URLhaus' && Array.isArray(c.urls)) {
    c.urls = c.urls.slice(0, 100).map((u) => ({ url: u.url, url_status: u.url_status, threat: u.threat, tags: u.tags }));
  }
  if (nome === 'ThreatFox' && Array.isArray(c.data)) c.data = c.data.slice(0, 50);
  if (nome === 'RDAP (registro do domínio)') c.entities = (c.entities ?? []).filter((e) => (e.roles ?? []).includes('registrar')).map((e) => ({ roles: e.roles, vcardArray: e.vcardArray }));
  return c;
}

const respostas = {};
for (const nome of FONTES) {
  let json;
  try { json = $(nome).first().json; } catch (erro) { continue; }
  if (json.statusCode === undefined) continue; // erro de rede: não guarda, a próxima análise tenta de novo
  respostas[nome] = { statusCode: json.statusCode, body: enxugar(nome, json.body) };
}

// Decisão do nó "Link relacionado" (não é resposta HTTP): guardada para o relatório sair igual no cache.
try { respostas['Link relacionado'] = { statusCode: 200, body: $('Link relacionado').first().json }; } catch (erro) { /* não executado */ }

const horas = Math.max(1, Number(config.cacheHoras) || 24);
const ttl = intel.falharam.length ? 3600 : horas * 3600;

return [{
  json: {
    chave: alvo.chaveCache,
    ttl,
    valor: JSON.stringify({ versao: VERSAO, urlFinal: alvo.urlFinal, em: new Date().toISOString(), respostas }),
  },
}];
