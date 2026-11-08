// Testes do código dos nós "Code", sem precisar do n8n.
// Uso:  node tests/testar-codigo.js
// Cada nó é executado com versões simuladas de $input e $('Nome do nó').
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const SRC = path.join(__dirname, '..', 'src');
const ler = (nome) => fs.readFileSync(path.join(SRC, nome), 'utf8');

function executar(arquivo, bibliotecas, entrada, outrosNos = {}) {
  const codigo = [...bibliotecas.map((b) => ler(`lib/${b}`)), ler(arquivo)].join('\n');
  const $input = { first: () => ({ json: entrada }), all: () => [{ json: entrada }] };
  const $ = (nome) => {
    if (!(nome in outrosNos)) throw new Error(`Nó "${nome}" não executado`);
    const item = { json: outrosNos[nome] };
    return { first: () => item, last: () => item };
  };
  // A sandbox do nó Code do n8n não tem a classe URL: aqui ela também fica indefinida.
  return new Function('$input', '$', 'URL', 'URLSearchParams', codigo)($input, $, undefined, undefined)[0].json;
}

let total = 0;
let falhas = 0;
function teste(nome, fn) {
  total++;
  try {
    fn();
    console.log(`  ok   ${nome}`);
  } catch (erro) {
    falhas++;
    console.log(`  FALHA ${nome}\n        ${erro.message}`);
  }
}

// ---------------------------------------------------------------- Validar URL
console.log('Validar URL');
const validar = (url) => executar('validar-url.js', ['ip.js', 'url.js'], { url, saltos: 0 });

for (const url of ['https://exemplo.com.br', 'exemplo.com.br', 'HTTPS://WWW.Exemplo.COM./a', 'http://www.exemplo.com/pagina?x=1', 'https://8.8.8.8', 'https://[2606:4700:4700::1111]/', 'https://exemplo.com:443', 'http://xn--maa-o0a.com.br']) {
  teste(`aceita ${url}`, () => assert.strictEqual(validar(url).ok, true, validar(url).motivo));
}
teste('sem protocolo vira https', () => assert.strictEqual(validar('exemplo.com.br').url, 'https://exemplo.com.br/'));
teste('URL é remontada em formato canônico', () => {
  assert.strictEqual(validar('HTTPS://WWW.Exemplo.COM.:443/a%20b?q=1#frag').url, 'https://www.exemplo.com/a%20b?q=1');
  assert.strictEqual(validar('https://exemplo.com/a"<b>').url, 'https://exemplo.com/a%22%3Cb%3E');
});
teste('nome do host é o que será acessado', () => assert.strictEqual(validar('https://exemplo.com.br/x').host, 'exemplo.com.br'));

const recusadas = [
  '', 'ftp://exemplo.com', 'file:///etc/passwd', 'javascript:alert(1)', 'gopher://exemplo.com',
  'http://localhost', 'http://localhost.', 'http://teste.localhost', 'http://n8n:5678', 'http://redis',
  'http://ng-soc-chamados-glpi-1', 'http://servidor.local', 'http://api.internal',
  'http://127.0.0.1', 'http://127.1', 'http://2130706433', 'http://0x7f000001', 'http://0177.0.0.1',
  'http://10.0.0.5', 'http://172.27.0.3', 'http://192.168.1.1', 'http://169.254.169.254/latest/meta-data/',
  'http://100.64.0.1', 'http://0.0.0.0', 'http://[::1]', 'http://[::ffff:127.0.0.1]', 'http://[fd00::1]',
  'http://[fe80::1]', 'http://[64:ff9b::a00:1]', 'https://exemplo.com:8443', 'https://exemplo.com:22',
  'https://usuario:senha@exemplo.com', 'https://exemplo.com@127.0.0.1', 'https://exemplo.com\\@127.0.0.1',
  'https://exemplo.com\\.127.0.0.1', 'http://0x7f.0.0.1', 'http://127.000.000.001', 'http://1.2.3', 'http://[::1%25eth0]',
  'https://exemplo .com', 'https://maçã.com.br', 'https://exemplo.com:0080abc', 'https://-exemplo.com', 'https://exem_plo.com',
  'https://servidor.lan', 'http://8.8.8.8:8080',
];
for (const url of recusadas) {
  teste(`recusa ${url || '(vazio)'}`, () => assert.strictEqual(validar(url).ok, false));
}

// ---------------------------------------------------------------- Verificar DNS
console.log('Verificar DNS');
const alvo = { ok: true, url: 'https://exemplo.com.br/', host: 'exemplo.com.br', ehIP: false, saltos: 0, cadeia: [] };
const dns = (ipv4, ipv6, status = 0) => executar('verificar-dns.js', ['ip.js'],
  { Status: 0, Answer: ipv6.map((data) => ({ type: 28, data })) },
  { 'Validar URL': alvo, 'DNS (IPv4)': { Status: status, Answer: ipv4.map((data) => ({ type: 1, data })) } });

teste('IP público passa', () => assert.deepStrictEqual(dns(['93.184.215.14'], ['2606:2800:21f:cb07:6820:80da:af6b:8b2c']).ips.length, 2));
teste('domínio que aponta para 127.0.0.1 é recusado', () => assert.strictEqual(dns(['127.0.0.1'], []).ok, false));
teste('domínio que aponta para rede do Docker é recusado', () => assert.strictEqual(dns(['172.27.0.5'], []).ok, false));
teste('um IP interno no meio de públicos já recusa', () => assert.strictEqual(dns(['8.8.8.8', '10.1.2.3'], []).ok, false));
teste('IPv6 interno é recusado', () => assert.strictEqual(dns(['8.8.8.8'], ['fd12::1']).ok, false));
teste('domínio inexistente explica o motivo', () => assert.match(dns([], [], 3).motivo, /não existe/));
teste('CNAME é ignorado', () => {
  const r = executar('verificar-dns.js', ['ip.js'], { Status: 0 }, {
    'Validar URL': alvo,
    'DNS (IPv4)': { Status: 0, Answer: [{ type: 5, data: 'cdn.exemplo.net.' }, { type: 1, data: '8.8.4.4' }] },
  });
  assert.deepStrictEqual(r.ips, ['8.8.4.4']);
});

// ---------------------------------------------------------------- Tratar resposta
console.log('Tratar resposta');
const verificado = { ...alvo, ips: ['8.8.8.8'], urlOriginal: 'http://exemplo.com.br' };
const tratar = (resposta, saltos = 0) => executar('tratar-resposta.js', ['ip.js', 'url.js'], resposta,
  { 'Verificar DNS': { ...verificado, saltos }, 'Configuração': { limiteConteudo: 100 } });

teste('redirecionamento relativo vira URL completa', () => {
  const r = tratar({ statusCode: 301, headers: { Location: '/novo' } });
  assert.strictEqual(r.acao, 'redirecionar');
  assert.strictEqual(r.url, 'https://exemplo.com.br/novo');
  assert.strictEqual(r.saltos, 1);
});
for (const [destino, esperado] of [
  ['https://outro.com/x', 'https://outro.com/x'],
  ['//cdn.exemplo.com/a', 'https://cdn.exemplo.com/a'],
  ['pagina2?x=1', 'https://exemplo.com.br/pagina2?x=1'],
  ['?lang=pt', 'https://exemplo.com.br/?lang=pt'],
  ['http://127.0.0.1/admin', 'http://127.0.0.1/admin'],
]) {
  teste(`Location "${destino}" vira ${esperado}`, () => assert.strictEqual(tratar({ statusCode: 302, headers: { location: destino } }).url, esperado));
}
teste('redirecionamento para IP interno é recusado na nova validação', () => {
  const proxima = tratar({ statusCode: 302, headers: { location: 'http://169.254.169.254/' } });
  assert.strictEqual(validar(proxima.url).ok, false);
});
teste('para de seguir depois de 5 redirecionamentos', () => {
  const r = tratar({ statusCode: 302, headers: { location: 'https://outro.com' } }, 5);
  assert.strictEqual(r.acao, 'analisar');
  assert.strictEqual(r.parouNoLimite, true);
});
teste('corta o conteúdo no limite e remove base64', () => {
  const html = '<img src="data:image/png;base64,' + 'A'.repeat(500) + '">' + 'x'.repeat(500);
  const r = tratar({ statusCode: 200, headers: { 'Content-Type': 'text/html' }, data: html });
  assert.strictEqual(r.conteudo.length, 100);
  assert.strictEqual(r.conteudoTruncado, true);
  assert.ok(r.conteudo.includes('[base64 removido]'));
  assert.strictEqual(r.cabecalhos['content-type'], 'text/html');
});

// ---------------------------------------------------------------- Biblioteca de domínio
console.log('Domínio e IOCs');
const libDominio = (expr) => new Function(`${ler('lib/dominio.js')}\nreturn ${expr};`)();
for (const [host, esperado] of [['www.loja.exemplo.com.br', 'exemplo.com.br'], ['a.b.exemplo.com', 'exemplo.com'], ['exemplo.com', 'exemplo.com'], ['www.bbc.co.uk', 'bbc.co.uk'], ['sub.exemplo.io', 'exemplo.io']]) {
  teste(`domínio registrado de ${host} é ${esperado}`, () => assert.strictEqual(libDominio(`dominioRegistravel(${JSON.stringify(host)})`), esperado));
}
teste('ID de URL do VirusTotal (base64url sem =)', () => {
  assert.strictEqual(libDominio("base64Url('https://github.com/')"), 'aHR0cHM6Ly9naXRodWIuY29tLw');
  assert.strictEqual(libDominio("base64Url('https://github.com/zzz-nao-existe-123456')"), 'aHR0cHM6Ly9naXRodWIuY29tL3p6ei1uYW8tZXhpc3RlLTEyMzQ1Ng');
});
teste('IOC desarmado', () => {
  assert.strictEqual(libDominio("desarmar('https://mal.exemplo.com/a.b?x=1.2')"), 'hxxps://mal[.]exemplo[.]com/a.b?x=1.2');
  assert.strictEqual(libDominio("desarmar('http://1.2.3.4/')"), 'hxxp://1[.]2[.]3[.]4/');
  assert.strictEqual(libDominio("desarmar('mal.com')"), 'mal[.]com');
});

// ---------------------------------------------------------------- Modo só reputação
console.log('Modo só reputação');
const dnsReputacao = (ipv4, status = 0) => executar('verificar-dns.js', ['ip.js'], { Status: 0 },
  { 'Validar URL': alvo, 'Configuração': { modo: 'reputacao' }, 'DNS (IPv4)': { Status: status, Answer: ipv4.map((data) => ({ type: 1, data })) } });
teste('domínio derrubado (NXDOMAIN) ainda é consultado', () => {
  const r = dnsReputacao([], 3);
  assert.strictEqual(r.ok, true);
  assert.match(r.avisoDns, /não existe/);
});
teste('IP interno é descartado, mas a consulta segue', () => {
  const r = dnsReputacao(['127.0.0.1', '8.8.8.8']);
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.ips, ['8.8.8.8']);
});
teste('modo completo continua recusando IP interno', () => assert.strictEqual(executar('verificar-dns.js', ['ip.js'], { Status: 0 },
  { 'Validar URL': alvo, 'Configuração': { modo: 'completa' }, 'DNS (IPv4)': { Status: 0, Answer: [{ type: 1, data: '10.0.0.1' }] } }).ok, false));

// ---------------------------------------------------------------- Processar resultados
console.log('Processar resultados');
const pagina = (cabecalhos, urlFinal = 'https://exemplo.com.br/', extra = {}) => ({
  urlOriginal: urlFinal, urlFinal, host: 'exemplo.com.br', ips: ['8.8.8.8'], status: 200, cabecalhos, cadeia: [], visitado: true, ...extra,
});
const preparar = (pag) => executar('preparar-consultas.js', ['ip.js', 'dominio.js'], pag, { 'Configuração': { modo: 'completa', contexto: '' } });
const processar = (cabecalhos, urlFinal, extra) => executar('processar-resultados.js', [], {}, {
  'Preparar consultas': preparar(pagina(cabecalhos, urlFinal, extra)),
}).auditoria;

const completo = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'self'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=()',
};
teste('todos os cabeçalhos: nota A+', () => assert.strictEqual(processar(completo).nota, 'A+'));
teste('frame-ancestors substitui X-Frame-Options', () => assert.ok(!processar(completo).achados.some((a) => a.titulo.includes('clickjacking'))));
teste('sem nenhum cabeçalho: nota F', () => assert.strictEqual(processar({}).nota, 'F'));
teste("CSP com 'unsafe-inline' baixa para A-", () => assert.strictEqual(processar({ ...completo, 'content-security-policy': "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'" }).nota, 'A-'));
teste('sem HTTPS a nota não passa de D', () => {
  const r = processar({ ...completo }, 'http://exemplo.com.br/');
  assert.strictEqual(r.nota, 'D');
  assert.ok(r.achados.some((a) => a.titulo === 'Site sem HTTPS'));
});
teste('cookie sem Secure/HttpOnly/SameSite gera achado', () => {
  const r = processar({ ...completo, 'set-cookie': ['sessao=abc; Path=/', 'ok=1; Secure; HttpOnly; SameSite=Lax'] });
  const cookies = r.achados.filter((a) => a.titulo.startsWith('Cookie'));
  assert.strictEqual(cookies.length, 1);
  assert.match(cookies[0].titulo, /sessao.*Secure, HttpOnly, SameSite/);
});
teste('Server com versão gera achado de vazamento', () => assert.ok(processar({ ...completo, server: 'nginx/1.18.0' }).achados.some((a) => a.titulo.includes('server'))));
teste('só reputação: postura N/A e sem achados', () => {
  const r = processar({}, 'http://exemplo.com.br/', { visitado: false });
  assert.strictEqual(r.nota, 'N/A');
  assert.strictEqual(r.achados.length, 0);
});
teste('preparar consultas acha domínio, IP e hosts da cadeia', () => {
  const r = preparar(pagina({}, 'https://www.loja.exemplo.com.br/', { host: 'www.loja.exemplo.com.br', ips: ['2001:db8::1', '8.8.8.8'], cadeia: [{ url: 'https://bit.ly/abc' }, { url: 'https://www.loja.exemplo.com.br/' }] }));
  assert.strictEqual(r.dominio, 'exemplo.com.br');
  assert.strictEqual(r.ipPrincipal, '8.8.8.8');
  assert.deepStrictEqual(r.hostsCadeia, ['bit.ly']);
  assert.strictEqual(r.vtEntidade, 'domains/exemplo.com.br');
  assert.strictEqual(r.observatorio, true);
});

// ---------------------------------------------------------------- Consolidar inteligência
console.log('Consolidar inteligência');
const ok = (body, statusCode = 200) => ({ statusCode, body });
const vtStats = (malicious, extra = {}) => ok({ data: { attributes: { last_analysis_stats: { malicious, suspicious: 0, harmless: 60, undetected: 30 }, reputation: 0, ...extra } } });
const limpoBase = {
  'VirusTotal (URL)': vtStats(0),
  'VirusTotal (domínio)': vtStats(0, { creation_date: 946684800 }),
  'URLhaus': ok({ query_status: 'no_results' }),
  'ThreatFox': ok({ query_status: 'no_result', data: 'Your search did not yield any results' }),
  'OTX': ok({ pulse_info: { count: 0 }, validation: [] }),
  'AbuseIPDB': ok({ data: { abuseConfidenceScore: 0, totalReports: 0, usageType: 'Data Center', isp: 'Exemplo', countryCode: 'BR' } }),
  'Shodan InternetDB': ok({ ports: [80, 443], vulns: [], tags: [] }),
  'RDAP (registro do domínio)': ok({ events: [{ eventAction: 'registration', eventDate: '2000-01-01T00:00:00Z' }] }),
  'DNS (SPF)': ok({ Answer: [{ type: 16, data: 'v=spf1 -all' }] }),
  'DNS (DMARC)': ok({ Answer: [{ type: 16, data: 'v=DMARC1; p=reject' }] }),
  'Mozilla Observatory': ok({ grade: 'A', score: 90, tests_failed: 1, tests_quantity: 10 }),
  'urlscan (busca)': ok({ total: 0, results: [] }),
};
const consolidar = (respostas = {}, cabecalhos = completo, urlFinal = 'https://exemplo.com.br/', extra = {}) => {
  const prep = preparar(pagina(cabecalhos, urlFinal, extra));
  const aud = executar('processar-resultados.js', [], {}, { 'Preparar consultas': prep });
  return executar('consolidar-inteligencia.js', ['dominio.js'], aud, { ...limpoBase, ...respostas, 'Preparar consultas': prep }).auditoria;
};
teste('site limpo e bem configurado: limpo e nota alta', () => {
  const r = consolidar().inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'limpo');
  assert.ok(r.notaAutomatica >= 90, `nota ${r.notaAutomatica}`);
  assert.strictEqual(r.falharam.length, 0, r.falharam.join('; '));
});
teste('URL exata no URLhaus (online): malicioso e nota até 20', () => {
  const r = consolidar({ 'URLhaus': ok({ query_status: 'ok', url_count: '1', blacklists: { spamhaus_dbl: 'not listed' }, urls: [{ url: 'https://exemplo.com.br/', url_status: 'online', threat: 'malware_download', tags: ['GuLoader'] }] }) }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'malicioso');
  assert.ok(r.notaAutomatica <= 20);
});
teste('plataforma popular com URLs de terceiros no URLhaus/ThreatFox NÃO vira malicioso', () => {
  const r = consolidar({
    'VirusTotal (domínio)': vtStats(0, { popularity_ranks: { Majestic: { rank: 30 } } }),
    'URLhaus': ok({ query_status: 'ok', url_count: '61789', blacklists: { spamhaus_dbl: 'not listed' }, urls: [{ url: 'https://exemplo.com.br/usuario/arquivo.exe', url_status: 'online', threat: 'malware_download' }] }),
    'ThreatFox': ok({ query_status: 'ok', data: [{ ioc: 'https://exemplo.com.br/usuario/x.zip', malware_printable: 'X', threat_type: 'payload_delivery', confidence_level: 100 }] }),
  }).inteligencia;
  assert.strictEqual(r.popular, true);
  assert.strictEqual(r.vereditoAutomatico, 'limpo');
});
teste('mesmo caso sem popularidade vira malicioso (malware online no host)', () => {
  const r = consolidar({
    'URLhaus': ok({ query_status: 'ok', url_count: '2', blacklists: { spamhaus_dbl: 'not listed' }, urls: [{ url: 'https://exemplo.com.br/x.exe', url_status: 'online', threat: 'malware_download' }] }),
  }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'malicioso');
});
teste('1 motor isolado no VirusTotal não condena', () => assert.strictEqual(consolidar({ 'VirusTotal (domínio)': vtStats(1, { creation_date: 946684800 }) }).inteligencia.vereditoAutomatico, 'limpo'));
teste('ThreatFox com o host exato: malicioso', () => {
  const r = consolidar({ 'ThreatFox': ok({ query_status: 'ok', data: [{ ioc: 'exemplo.com.br:443', malware_printable: 'Cobalt Strike', threat_type: 'botnet_cc', confidence_level: 100 }] }) }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'malicioso');
});
teste('domínio com 5 dias: suspeito', () => {
  const recente = new Date(Date.now() - 5 * 86400000).toISOString();
  const r = consolidar({ 'RDAP (registro do domínio)': ok({ events: [{ eventAction: 'registration', eventDate: recente }] }) }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'suspeito');
  assert.strictEqual(r.fontes.registro.idadeDias, 5);
});
teste('todas as fontes fora: indeterminado, sem travar', () => {
  const fora = Object.fromEntries(Object.keys(limpoBase).map((k) => [k, { error: { message: 'getaddrinfo ENOTFOUND' } }]));
  const r = consolidar(fora).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'indeterminado');
  assert.ok(r.falharam.length >= 6);
});
teste('cota esgotada do VirusTotal é explicada', () => assert.ok(consolidar({ 'VirusTotal (URL)': ok({ error: { code: 'QuotaExceededError' } }, 429) }).inteligencia.falharam.some((x) => /cota/.test(x))));
teste('sem SPF e DMARC gera sinais', () => {
  const r = consolidar({ 'DNS (SPF)': ok({ Status: 0 }), 'DNS (DMARC)': ok({ Status: 3 }) }).inteligencia;
  assert.ok(r.sinais.some((s) => /SPF/.test(s.texto)) && r.sinais.some((s) => /DMARC/.test(s.texto)));
});

// ---------------------------------------------------------------- urlscan.io
console.log('urlscan.io');
const resultadoUrlscan = ({ malicioso = false, marcas = [], data = new Date().toISOString(), visibilidade = 'private', dominio = 'exemplo.com.br', dominios = ['exemplo.com.br', 'cdn.exemplo.net'] } = {}) => ok({
  task: { uuid: '01a1b170-a56a-779c-80a2-f8a33c16c80c', time: data, visibility: visibilidade, url: 'https://exemplo.com.br/' },
  page: { url: 'https://exemplo.com.br/', domain: dominio, ip: '8.8.8.8', country: 'BR', title: 'Entrar', tlsIssuer: 'R3', tlsAgeDays: 3 },
  verdicts: { overall: { malicious: malicioso, score: malicioso ? 100 : 0, brands: marcas, categories: malicioso ? ['phishing'] : [] } },
  lists: { domains: dominios, ips: ['8.8.8.8'], countries: ['BR'] },
});
const enviado = ok({ uuid: '01a1b170-a56a-779c-80a2-f8a33c16c80c', message: 'Submission successful' });
teste('visibilidade do urlscan nunca é pública', () => {
  for (const v of ['public', 'PUBLIC', '', undefined, 'unlisted', 'private']) {
    const r = executar('preparar-consultas.js', ['ip.js', 'dominio.js'], pagina({}), { 'Configuração': { modo: 'completa', urlscanVisibilidade: v } });
    assert.ok(['private', 'unlisted'].includes(r.urlscanVisibilidade), `${v} -> ${r.urlscanVisibilidade}`);
  }
});
teste('análise só é pedida no modo completo', () => {
  assert.strictEqual(preparar(pagina({})).urlscanAnalisar, true);
  assert.strictEqual(preparar(pagina({}, undefined, { visitado: false })).urlscanAnalisar, false);
});
teste('análise própria limpa: continua limpo e entra nas fontes', () => {
  const r = consolidar({ 'urlscan (enviar análise)': enviado, 'urlscan (resultado)': resultadoUrlscan() }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'limpo');
  assert.ok(r.consultadas.includes('urlscan.io'));
  assert.strictEqual(r.fontes.urlscan.analise.propria, true);
});
teste('urlscan malicioso imitando marca: malicioso + marca imitada', () => {
  const r = consolidar({ 'urlscan (enviar análise)': enviado, 'urlscan (resultado)': resultadoUrlscan({ malicioso: true, marcas: [{ name: 'Itaú', key: 'itau' }] }) }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'malicioso');
  assert.ok(r.sinais.some((s) => /imitar a marca Itaú/.test(s.texto)));
});
teste('marca do próprio domínio não conta como imitação', () => {
  const r = consolidar({ 'urlscan (enviar análise)': enviado, 'urlscan (resultado)': resultadoUrlscan({ marcas: ['Exemplo'] }) }).inteligencia;
  assert.ok(!r.sinais.some((s) => /imitar/.test(s.texto)));
});
teste('só reputação: análise anterior antiga e maliciosa pesa pouco', () => {
  const antiga = new Date(Date.now() - 100 * 86400000).toISOString();
  const r = consolidar({ 'urlscan (última análise)': resultadoUrlscan({ malicioso: true, data: antiga, visibilidade: 'public' }) }, {}, 'https://exemplo.com.br/', { visitado: false }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'suspeito');
  assert.strictEqual(r.fontes.urlscan.analise.propria, false);
});
teste('tag "phishing" no histórico sozinha não condena', () => {
  const r = consolidar({ 'urlscan (busca)': ok({ total: 3, results: [{ task: { time: '2026-11-06T14:10:00Z', tags: ['phishing', 'possiblethreat'] }, page: { url: 'https://exemplo.com.br/' } }] }) }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'limpo');
  assert.deepStrictEqual(r.fontes.urlscan.historico.tags, ['phishing', 'possiblethreat']);
});
teste('envio recusado pelo urlscan é explicado e usa a análise anterior', () => {
  const r = consolidar({ 'urlscan (enviar análise)': ok({ message: 'Scan prevented ...', description: 'domínio bloqueado' }, 400), 'urlscan (última análise)': resultadoUrlscan({ visibilidade: 'public' }) }).inteligencia;
  assert.match(r.fontes.urlscan.erroEnvio, /Scan prevented/);
  assert.strictEqual(r.fontes.urlscan.analise.propria, false);
});
teste('análise que não terminou a tempo deixa link para ver depois', () => {
  const r = consolidar({ 'urlscan (enviar análise)': enviado, 'urlscan (resultado)': ok({ message: 'not found' }, 404) }).inteligencia;
  assert.match(r.fontes.urlscan.erroEnvio, /não terminou/);
  assert.match(r.fontes.urlscan.linkPendente, /^https:\/\/urlscan\.io\/result\//);
});

// ---------------------------------------------------------------- Cache (Redis)
console.log('Cache');
const prepCache = preparar(pagina({}));
const usar = (cache) => executar('usar-cache.js', [], { cache }, { 'Preparar consultas': prepCache });
const montar = (respostas, falharam = []) => executar('montar-cache.js', [], {}, {
  ...respostas,
  'Preparar consultas': prepCache,
  'Configuração': { cacheHoras: 24 },
  'Consolidar inteligência': { auditoria: { inteligencia: { falharam } } },
});
teste('chave do cache muda com o modo', () => {
  const completa = executar('preparar-consultas.js', ['ip.js', 'dominio.js'], pagina({}), { 'Configuração': { modo: 'completa' } }).chaveCache;
  const reputacao = executar('preparar-consultas.js', ['ip.js', 'dominio.js'], pagina({}), { 'Configuração': { modo: 'reputacao' } }).chaveCache;
  assert.notStrictEqual(completa, reputacao);
  assert.match(completa, /^scanner:intel:completa:/);
});
teste('sem cache, cache estragado ou de outra URL: consulta normal', () => {
  assert.strictEqual(usar(null).hit, false);
  assert.strictEqual(usar('{isto não é json').hit, false);
  assert.strictEqual(usar(JSON.stringify({ versao: 1, urlFinal: 'https://outro.com/', respostas: {} })).hit, false);
  assert.strictEqual(usar(JSON.stringify({ versao: 99, urlFinal: prepCache.urlFinal, respostas: {} })).hit, false);
});
teste('ida e volta: o veredito do cache é o mesmo da consulta ao vivo', () => {
  const vivas = { ...limpoBase, 'ThreatFox': ok({ query_status: 'ok', data: [{ ioc: 'exemplo.com.br', malware_printable: 'X', threat_type: 'botnet_cc', confidence_level: 90 }] }) };
  const aoVivo = consolidar(vivas).inteligencia;
  const guardado = montar(vivas);
  const lido = usar(guardado.valor);
  assert.strictEqual(lido.hit, true);
  // Consolida SÓ com o cache (os nós de consulta "não rodaram").
  const prep = preparar(pagina(completo));
  const aud = executar('processar-resultados.js', [], {}, { 'Preparar consultas': prep });
  const doCache = executar('consolidar-inteligencia.js', ['dominio.js'], aud, { 'Preparar consultas': prep, 'Usar cache': lido }).auditoria.inteligencia;
  assert.strictEqual(doCache.vereditoAutomatico, aoVivo.vereditoAutomatico);
  assert.strictEqual(doCache.vereditoAutomatico, 'malicioso');
  assert.strictEqual(doCache.cache.usado, true);
});
teste('cache guarda 24 h, ou 1 h se uma fonte falhou', () => {
  assert.strictEqual(montar(limpoBase).ttl, 86400);
  assert.strictEqual(montar(limpoBase, ['VirusTotal (URL): cota esgotada']).ttl, 3600);
});
teste('erro de rede não vai para o cache', () => {
  const r = JSON.parse(montar({ ...limpoBase, 'OTX': { error: { message: 'ETIMEDOUT' } } }).valor);
  assert.ok(!('OTX' in r.respostas));
  assert.ok('URLhaus' in r.respostas);
});
teste('cache é enxuto (VirusTotal sem whois, urlscan sem requisições)', () => {
  const r = JSON.parse(montar({
    ...limpoBase,
    'VirusTotal (domínio)': vtStats(0, { whois: 'x'.repeat(50000), last_analysis_results: { A: { category: 'harmless' }, B: { category: 'malicious', result: 'phishing' } } }),
    'urlscan (resultado)': ok({ task: { uuid: 'u' }, data: { requests: 'y'.repeat(50000) }, lists: { domains: ['a.com'], urls: ['z'] } }),
  }).valor);
  const at = r.respostas['VirusTotal (domínio)'].body.data.attributes;
  assert.ok(!at.whois);
  assert.deepStrictEqual(Object.keys(at.last_analysis_results), ['B']);
  assert.ok(!r.respostas['urlscan (resultado)'].body.data);
  assert.ok(JSON.stringify(r).length < 10000);
});

// ---------------------------------------------------------------- Parecer final (travas da IA)
console.log('Parecer final');
const parecer = (aud, saidaIA) => {
  const dossie = executar('montar-dossie.js', ['dominio.js'], {}, { 'Consolidar inteligência': { auditoria: aud }, 'IA - conteúdo': { output: 'nada' } });
  return executar('parecer-final.js', ['dominio.js'], saidaIA, { 'Consolidar inteligência': { auditoria: aud }, 'Montar dossiê': dossie }).auditoria;
};
const respostaIA = (obj) => ({ output: '```json\n' + JSON.stringify(obj) + '\n```' });
const audLimpo = consolidar();
const audMalicioso = consolidar({ 'ThreatFox': ok({ query_status: 'ok', data: [{ ioc: 'exemplo.com.br', malware_printable: 'X', threat_type: 'botnet_cc', confidence_level: 90 }] }) });
teste('dossiê não leva o HTML cru para a IA analista', () => {
  const d = executar('montar-dossie.js', ['dominio.js'], {}, { 'Consolidar inteligência': { auditoria: { ...audLimpo, conteudo: '<html>SEGREDO-DO-HTML</html>' } } });
  assert.ok(!d.dossie.includes('SEGREDO-DO-HTML'));
  assert.match(d.dossie, /Veredito automático: limpo/);
});
teste('parecer da IA válido é usado (JSON dentro de ```)', () => {
  const r = parecer(audLimpo, respostaIA({ veredito: 'limpo', nota: 88, confianca: 'alta', resumo: 'ok', evidencias: ['a'], acoes: ['liberar'] })).parecer;
  assert.strictEqual(r.origem, 'ia');
  assert.strictEqual(r.nota, 88);
  assert.deepStrictEqual(r.acoes, ['liberar']);
});
teste('IA não consegue desmentir evidência forte', () => {
  const r = parecer(audMalicioso, respostaIA({ veredito: 'limpo', nota: 100, confianca: 'alta', resumo: 'site seguro' })).parecer;
  assert.strictEqual(r.veredito, 'malicioso');
  assert.ok(r.nota <= 30);
  assert.ok(r.avisos.length >= 1);
});
teste('nota da IA fica a até 30 pontos da automática', () => {
  const r = parecer(audLimpo, respostaIA({ veredito: 'limpo', nota: 5, confianca: 'baixa', resumo: 'x' })).parecer;
  assert.strictEqual(r.nota, audLimpo.inteligencia.notaAutomatica - 30);
});
teste('IA fora do formato: vale o parecer automático', () => {
  const r = parecer(audMalicioso, { output: 'Desculpe, não consigo.' }).parecer;
  assert.strictEqual(r.origem, 'automatica');
  assert.strictEqual(r.veredito, 'malicioso');
  assert.ok(r.acoes.length > 0);
});
teste('IA com erro de API: vale o parecer automático', () => assert.match(parecer(audLimpo, { error: 'API key not valid' }).parecer.resumo, /API key not valid/));

// ---------------------------------------------------------------- Encurtadores (link relacionado)
console.log('Encurtadores');
const LIBS_REL = ['ip.js', 'url.js', 'dominio.js', 'encurtador.js'];
const relacionar = (pag, vtUrl) => executar('link-relacionado.js', LIBS_REL, {}, { 'Preparar consultas': preparar(pagina(completo, pag.urlFinal, pag)), ...(vtUrl ? { 'VirusTotal (URL)': vtUrl } : {}) });
const curtoSemVisita = { urlOriginal: 'https://bit.ly/abc', urlFinal: 'https://bit.ly/abc', host: 'bit.ly', visitado: false, cabecalhos: {} };
teste('reconhece encurtadores conhecidos (e subdomínio)', () => {
  const ehEnc = new Function(`${ler('lib/encurtador.js')}; return ehEncurtador;`)();
  for (const h of ['bit.ly', 'www.bit.ly', 'TINYURL.com', 't.co', 'encurtador.com.br']) assert.ok(ehEnc(h), h);
  for (const h of ['exemplo.com.br', 'notbit.ly', 'bit.ly.exemplo.com']) assert.ok(!ehEnc(h), h);
});
teste('modo completo: link original do encurtador vira link relacionado', () => {
  const r = relacionar({ urlOriginal: 'https://bit.ly/abc', urlFinal: 'https://exemplo.com.br/', cadeia: [{ url: 'https://bit.ly/abc', status: 301 }, { url: 'https://exemplo.com.br/', status: 200 }] });
  assert.strictEqual(r.consultar, true);
  assert.strictEqual(r.papel, 'origem');
  assert.strictEqual(r.url, 'https://bit.ly/abc');
  assert.strictEqual(r.encurtador, 'bit.ly');
});
teste('redirecionamento no mesmo domínio não gera consulta extra', () => {
  const r = relacionar({ urlOriginal: 'https://www.exemplo.com.br/', urlFinal: 'https://exemplo.com.br/' });
  assert.strictEqual(r.consultar, false);
});
teste('só reputação: destino vem do VirusTotal (sem abrir o encurtador)', () => {
  const r = relacionar(curtoSemVisita, ok({ data: { attributes: { last_final_url: 'https://Phish.Exemplo.net/login?x=1' } } }));
  assert.strictEqual(r.papel, 'destino');
  assert.strictEqual(r.url, 'https://phish.exemplo.net/login?x=1');
  assert.strictEqual(r.host, 'phish.exemplo.net');
  assert.strictEqual(r.encurtador, 'bit.ly');
  assert.strictEqual(r.destinoDesconhecido, false);
});
teste('só reputação: encurtador com destino desconhecido', () => {
  const r = relacionar(curtoSemVisita, ok({ data: { attributes: {} } }));
  assert.strictEqual(r.consultar, false);
  assert.strictEqual(r.destinoDesconhecido, true);
});
teste('destino estranho do VirusTotal (javascript:) é ignorado', () => {
  const r = relacionar(curtoSemVisita, ok({ data: { attributes: { last_final_url: 'javascript:alert(1)' } } }));
  assert.strictEqual(r.consultar, false);
});
const relDestino = { consultar: true, papel: 'destino', url: 'https://phish.exemplo.net/login', host: 'phish.exemplo.net', vtUrlId: 'x', encurtador: 'bit.ly', destinoDesconhecido: false };
teste('destino do encurtador malicioso no VirusTotal deixa o veredito malicioso', () => {
  const r = consolidar({ 'Link relacionado': relDestino, 'VirusTotal (link relacionado)': vtStats(6) }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'malicioso');
  assert.strictEqual(r.fontes.linkRelacionado.vt.malicioso, 6);
  assert.ok(r.consultadas.includes('VirusTotal (destino)'));
});
teste('destino do encurtador listado no URLhaus (online) é malicioso', () => {
  const r = consolidar({ 'Link relacionado': relDestino, 'VirusTotal (link relacionado)': ok({}, 404), 'URLhaus (link relacionado)': ok({ query_status: 'ok', url_status: 'online', threat: 'malware_download' }) }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'malicioso');
  assert.strictEqual(r.fontes.linkRelacionado.vt.naoVista, true);
});
const relDesconhecido = { consultar: false, papel: '', url: '', host: '', vtUrlId: '', encurtador: 'bit.ly', destinoDesconhecido: true };
teste('encurtador com destino desconhecido nunca sai "limpo"', () => {
  const r = consolidar({ 'Link relacionado': relDesconhecido }).inteligencia;
  assert.strictEqual(r.vereditoAutomatico, 'indeterminado');
  assert.ok(r.sinais.some((s) => s.fonte === 'Encurtador'));
});
teste('IA não consegue chamar de "limpo" um encurtador com destino desconhecido', () => {
  const r = parecer(consolidar({ 'Link relacionado': relDesconhecido }), respostaIA({ veredito: 'limpo', nota: 95, confianca: 'alta', resumo: 'ok' })).parecer;
  assert.strictEqual(r.veredito, 'indeterminado');
  assert.ok(r.nota <= 80);
});
teste('relatório mostra o destino desarmado no texto e nos IOCs', () => {
  const aud = parecer(consolidar({ 'Link relacionado': relDestino, 'VirusTotal (link relacionado)': vtStats(6) }), { error: 'sem IA' });
  const r = executar('gerar-relatorio.js', ['html.js', 'dominio.js'], { auditoria: aud });
  assert.ok(r.textoChamado.includes('Destino conhecido (VirusTotal): hxxps://phish[.]exemplo[.]net/login'));
  assert.ok(r.textoChamado.includes('- URL: hxxps://phish[.]exemplo[.]net/login'));
  assert.ok(r.textoChamado.includes('VirusTotal (destino)'));
  assert.ok(!r.html.includes('https://phish.exemplo.net'));
});
teste('cache guarda as consultas e a decisão do link relacionado', () => {
  const nosRel = { ...limpoBase, 'Link relacionado': relDestino, 'VirusTotal (link relacionado)': vtStats(6) };
  const prep = preparar(pagina(completo));
  const aud = consolidar({ 'Link relacionado': relDestino, 'VirusTotal (link relacionado)': vtStats(6) });
  const c = JSON.parse(executar('montar-cache.js', [], {}, { ...nosRel, 'Preparar consultas': prep, 'Configuração': { cacheHoras: 24 }, 'Consolidar inteligência': { auditoria: aud } }).valor);
  assert.strictEqual(c.versao, 2);
  assert.ok(c.respostas['VirusTotal (link relacionado)']);
  assert.strictEqual(c.respostas['Link relacionado'].body.url, relDestino.url);
});

// ---------------------------------------------------------------- Gerar relatório (segurança do HTML)
console.log('Gerar relatório');
const malicioso = '<script>alert(1)</script><img src=x onerror=alert(2)>';
const audRelatorio = consolidar({
  'VirusTotal (domínio)': vtStats(2, { categories: { x: malicioso }, last_analysis_results: { M: { category: 'malicious', result: malicioso } } }),
  'Shodan InternetDB': ok({ ports: [3389], vulns: [malicioso], tags: [malicioso] }),
  'urlscan (enviar análise)': enviado,
  'urlscan (resultado)': ok({ task: { uuid: 'abc', time: '2026-11-06', visibility: 'private' }, page: { title: malicioso, domain: 'exemplo.com.br' }, verdicts: { overall: { brands: [malicioso] } }, lists: { domains: ['mal.exemplo.net', malicioso] } }),
}, { ...completo, server: malicioso, 'x-teste': '"><svg onload=alert(3)>', 'set-cookie': [`${malicioso}=1`] });
audRelatorio.urlOriginal = 'javascript:alert(4)';
const final = parecer(audRelatorio, respostaIA({ veredito: 'suspeito', nota: 50, confianca: 'media', resumo: malicioso, evidencias: [malicioso], acoes: [malicioso], mitre: [malicioso] }));
final.iaConteudo = { ok: true, texto: `## Título ${malicioso}\n- item **negrito** \`<b>código</b>\`\n\`\`\`\n${malicioso}\n\`\`\`` };
const relatorio = executar('gerar-relatorio.js', ['html.js', 'dominio.js'], { auditoria: final });

teste('nenhuma tag vinda do site, das fontes ou da IA aparece crua', () => {
  assert.ok(!/<script|<img|<svg|<[^>]*\son(error|load)=/i.test(relatorio.html), 'encontrou HTML não escapado');
  assert.ok(!relatorio.html.includes('<script'));
  assert.ok(!relatorio.html.includes('<svg'));
  assert.ok(!relatorio.html.includes('<img'));
  assert.ok(!relatorio.html.includes('<b>código'));
});
teste('link javascript: não vira link', () => assert.ok(!relatorio.html.includes('href="javascript:')));
teste('endereço do alvo não vira link clicável (sai desarmado)', () => {
  assert.ok(!relatorio.html.includes('href="https://exemplo.com.br'));
  assert.ok(relatorio.textoChamado.includes('exemplo[.]com[.]br'));
});
teste('urlscan aparece no relatório, com domínios desarmados', () => {
  assert.match(relatorio.html, /urlscan\.io/);
  assert.ok(relatorio.html.includes('mal[.]exemplo[.]net'));
  assert.ok(relatorio.html.includes('href="https://urlscan.io/result/abc/"'));
});
teste('Markdown da IA é formatado', () => {
  assert.ok(relatorio.html.includes('<strong>negrito</strong>'));
  assert.ok(relatorio.html.includes('<h3'));
  assert.ok(relatorio.html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
});
teste('assunto do e-mail tem veredito, host e risco', () => assert.match(relatorio.assunto, /^\[SUSPEITO\] exemplo\.com\.br: risco \d+\/100/));
teste('risco mostrado é 100 menos a nota de segurança', () => assert.strictEqual(relatorio.risco, 100 - relatorio.nota));
teste('texto para copiar tem as seções do parecer e alvo desarmado', () => {
  for (const sec of ['RESUMO DO PARECER', 'ALVO', 'DETECÇÕES NAS FONTES', 'IOCs (desarmados)', 'FONTES CONSULTADAS']) assert.ok(relatorio.textoChamado.includes(sec), sec);
  assert.match(relatorio.textoChamado, /Risco: \d+\/100/);
  assert.ok(!/https?:\/\/exemplo\.com/.test(relatorio.textoChamado), 'alvo não pode sair armado');
});
teste('relatório do modo só reputação sai sem postura', () => {
  const aud = consolidar({}, {}, 'https://exemplo.com.br/', { visitado: false });
  const r = executar('gerar-relatorio.js', ['html.js', 'dominio.js'], { auditoria: parecer(aud, { error: 'sem IA' }) });
  assert.match(r.html, /Não avaliada/);
  assert.ok(!r.html.includes('Cabeçalhos recebidos'));
});

// ---------------------------------------------------------------- Página de erro
console.log('Página de erro');
teste('erro de certificado é explicado', () => {
  const r = executar('pagina-erro.js', ['html.js'], { error: { message: 'unable to verify the first certificate' } }, { 'Configuração': { url: 'https://x.com' } });
  assert.match(r.html, /certificado HTTPS/);
});
teste('motivo da validação é escapado', () => {
  const r = executar('pagina-erro.js', ['html.js'], { motivo: malicioso }, { 'Configuração': { url: malicioso } });
  assert.ok(!r.html.includes('<script'));
});

console.log(`\n${total - falhas}/${total} testes passaram.`);
process.exit(falhas ? 1 : 0);
