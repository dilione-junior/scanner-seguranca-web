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

// ---------------------------------------------------------------- Processar resultados
console.log('Processar resultados');
const processar = (cabecalhos, urlFinal = 'https://exemplo.com.br/', ia = {}) => executar('processar-resultados.js', [], {}, {
  'Tratar resposta': { urlOriginal: urlFinal, urlFinal, host: 'exemplo.com.br', ips: ['8.8.8.8'], status: 200, cabecalhos, cadeia: [] },
  'IA - configuração': ia.config ?? { output: 'ok' },
  'IA - conteúdo': ia.conteudo ?? { output: 'ok' },
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
teste('falha da IA vira aviso, não erro', () => {
  const r = processar(completo, undefined, { config: { error: 'API key not valid' } });
  assert.strictEqual(r.iaConfiguracao.ok, false);
  assert.match(r.iaConfiguracao.texto, /API key not valid/);
});

// ---------------------------------------------------------------- Gerar relatório (segurança do HTML)
console.log('Gerar relatório');
const malicioso = '<script>alert(1)</script><img src=x onerror=alert(2)>';
const auditoria = processar(
  { ...completo, server: malicioso, 'x-teste': '"><svg onload=alert(3)>', 'set-cookie': [`${malicioso}=1`] },
  'https://exemplo.com.br/',
  { config: { output: `## Título ${malicioso}\n- item **negrito** \`<b>código</b>\`\n\`\`\`\n${malicioso}\n\`\`\`` }, conteudo: { output: malicioso } },
);
auditoria.urlOriginal = 'javascript:alert(4)';
const relatorio = executar('gerar-relatorio.js', ['html.js'], { auditoria });

teste('nenhuma tag vinda do site ou da IA aparece crua', () => {
  assert.ok(!/<script|<img|<svg|onerror=|onload=/i.test(relatorio.html.replace(/&lt;[^]*?&gt;/g, '')), 'encontrou HTML não escapado');
  assert.ok(!relatorio.html.includes('<script'));
  assert.ok(!relatorio.html.includes('<svg'));
  assert.ok(!relatorio.html.includes('<img'));
  assert.ok(!relatorio.html.includes('<b>código'));
});
teste('link javascript: não vira link', () => assert.ok(!relatorio.html.includes('href="javascript:')));
teste('Markdown da IA é formatado', () => {
  assert.ok(relatorio.html.includes('<strong>negrito</strong>'));
  assert.ok(relatorio.html.includes('<h3'));
  assert.ok(relatorio.html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
});
teste('assunto do e-mail tem host e nota', () => assert.match(relatorio.assunto, /exemplo\.com\.br \(nota [A-F][+-]?\)/));

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
