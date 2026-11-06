// Nó "Processar resultados": calcula a nota e os achados automáticos A PARTIR DOS CABEÇALHOS REAIS.
// A nota não depende da IA (a IA pode errar ou inventar); o texto da IA entra só como análise complementar.
const dados = $('Tratar resposta').last().json;
const cab = dados.cabecalhos ?? {};
const ehHttps = String(dados.urlFinal).startsWith('https://');

function textoDaIA(nomeDoNo) {
  let json;
  try {
    json = $(nomeDoNo).last().json;
  } catch (erro) {
    return { ok: false, texto: 'A análise da IA não foi executada.' };
  }
  if (typeof json.output === 'string' && json.output.trim()) return { ok: true, texto: json.output.trim() };
  const erro = json.error?.message ?? json.error ?? 'resposta vazia';
  return { ok: false, texto: `A análise da IA não está disponível (${erro}). Confira a credencial do Google Gemini no n8n.` };
}

function valor(nome) {
  const v = cab[nome];
  if (v === undefined || v === null) return '';
  return Array.isArray(v) ? v.join(', ') : String(v);
}

const CABECALHOS = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'x-permitted-cross-domain-policies',
  'x-xss-protection',
];
const status = {};
for (const nome of CABECALHOS) status[nome] = { presente: valor(nome) !== '', valor: valor(nome) };

const csp = status['content-security-policy'].valor.toLowerCase();
const temFrameAncestors = /(^|;)\s*frame-ancestors\s/.test(csp);
const achados = [];
const achado = (nivel, titulo, detalhe, correcao = '') => achados.push({ nivel, titulo, detalhe, correcao });

// ---- Transporte ----
if (!ehHttps) {
  achado('alto', 'Site sem HTTPS',
    'A página final é servida por HTTP sem criptografia. Senhas, cookies e o próprio conteúdo podem ser lidos ou alterados no caminho.',
    'Instale um certificado TLS (ex.: Let\'s Encrypt) e redirecione todo o tráfego HTTP para HTTPS.');
}

// ---- Cabeçalhos de segurança ----
if (!status['content-security-policy'].presente) {
  achado('alto', 'Content-Security-Policy ausente',
    'Sem CSP, o navegador executa qualquer script injetado na página, o que facilita ataques de XSS.',
    "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'");
} else {
  const diretivaScript = (csp.match(/(?:^|;)\s*script-src\s+([^;]*)/) ?? csp.match(/(?:^|;)\s*default-src\s+([^;]*)/) ?? [])[1] ?? '';
  if (diretivaScript.includes("'unsafe-inline'") && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(diretivaScript)) {
    achado('medio', "CSP permite scripts inline ('unsafe-inline')",
      'A política existe, mas aceita scripts escritos dentro do HTML. Isso anula boa parte da proteção contra XSS.',
      "Troque 'unsafe-inline' por nonces ou hashes: script-src 'self' 'nonce-<valor-aleatório>'");
  }
  if (diretivaScript.includes("'unsafe-eval'")) {
    achado('medio', "CSP permite eval ('unsafe-eval')",
      'Permite transformar texto em código JavaScript em tempo de execução, o que amplia o impacto de um XSS.',
      "Remova 'unsafe-eval' e evite eval(), new Function() e setTimeout com texto.");
  }
}

if (ehHttps) {
  if (!status['strict-transport-security'].presente) {
    achado('alto', 'Strict-Transport-Security (HSTS) ausente',
      'Sem HSTS, o primeiro acesso pode ser feito por HTTP e interceptado (ataque de downgrade / SSL stripping).',
      'Strict-Transport-Security: max-age=31536000; includeSubDomains');
  } else {
    const maxAge = Number((status['strict-transport-security'].valor.match(/max-age=(\d+)/i) ?? [])[1] ?? 0);
    if (maxAge < 15552000) {
      achado('baixo', 'HSTS com validade curta',
        `max-age=${maxAge} segundos (${Math.round(maxAge / 86400)} dias). O recomendado é pelo menos 6 meses; o ideal é 1 ano.`,
        'Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
  }
}

if (status['x-content-type-options'].valor.toLowerCase().trim() !== 'nosniff') {
  achado('medio', 'X-Content-Type-Options ausente ou inválido',
    'O navegador pode "adivinhar" o tipo de um arquivo e executar como script algo que deveria ser texto ou imagem.',
    'X-Content-Type-Options: nosniff');
}

if (!status['x-frame-options'].presente && !temFrameAncestors) {
  achado('medio', 'Proteção contra clickjacking ausente',
    'Nem X-Frame-Options nem a diretiva frame-ancestors da CSP estão definidos. Outro site pode exibir esta página dentro de um iframe invisível e induzir cliques.',
    "Content-Security-Policy: frame-ancestors 'self'   (ou X-Frame-Options: SAMEORIGIN)");
}

if (!status['referrer-policy'].presente) {
  achado('baixo', 'Referrer-Policy ausente',
    'O endereço completo da página (que pode ter parâmetros sensíveis) pode ser enviado a outros sites nos links.',
    'Referrer-Policy: strict-origin-when-cross-origin');
}

if (!status['permissions-policy'].presente) {
  achado('baixo', 'Permissions-Policy ausente',
    'Não há restrição de recursos do navegador (câmera, microfone, localização) para a página e iframes.',
    'Permissions-Policy: camera=(), microphone=(), geolocation=()');
}

if (status['x-xss-protection'].presente && !/^\s*0\s*$/.test(status['x-xss-protection'].valor)) {
  achado('info', 'X-XSS-Protection é obsoleto',
    'Navegadores modernos ignoram este cabeçalho e o filtro antigo já causou falhas. A proteção correta é a CSP.',
    'Remova o cabeçalho ou use X-XSS-Protection: 0');
}

// ---- Vazamento de informações ----
for (const nome of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator']) {
  const v = valor(nome);
  if (v && (/\d/.test(v) || nome !== 'server')) {
    achado('baixo', `Cabeçalho ${nome} revela tecnologia`,
      `Valor: "${v}". Saber a tecnologia e a versão ajuda um atacante a procurar falhas conhecidas.`,
      `Remova o cabeçalho ${nome} ou esconda a versão na configuração do servidor.`);
  }
}

// ---- CORS ----
if (valor('access-control-allow-origin').trim() === '*') {
  const comCredenciais = valor('access-control-allow-credentials').toLowerCase() === 'true';
  achado(comCredenciais ? 'alto' : 'info', 'CORS liberado para qualquer origem',
    comCredenciais
      ? 'Access-Control-Allow-Origin: * junto com Allow-Credentials: true é uma configuração perigosa.'
      : 'Qualquer site pode ler as respostas desta página pelo navegador. Só é aceitável para conteúdo público (ex.: CDN).',
    'Liste explicitamente as origens permitidas em Access-Control-Allow-Origin.');
}

// ---- Cookies ----
const cookies = [].concat(cab['set-cookie'] ?? []).map(String);
for (const cookie of cookies) {
  const nome = cookie.split('=')[0].trim() || '(sem nome)';
  const atributos = cookie.toLowerCase();
  const faltando = [];
  if (ehHttps && !/;\s*secure/.test(atributos)) faltando.push('Secure');
  if (!/;\s*httponly/.test(atributos)) faltando.push('HttpOnly');
  if (!/;\s*samesite=/.test(atributos)) faltando.push('SameSite');
  if (faltando.length) {
    achado(faltando.includes('Secure') ? 'medio' : 'baixo', `Cookie "${nome}" sem ${faltando.join(', ')}`,
      'Secure impede envio por HTTP; HttpOnly impede leitura por JavaScript (roubo via XSS); SameSite reduz CSRF. HttpOnly pode faltar de propósito se o cookie precisa ser lido pelo JavaScript.',
      `Set-Cookie: ${nome}=...; Secure; HttpOnly; SameSite=Lax`);
  }
}

// ---- Nota (A+ a F), parecida com a do securityheaders.com ----
const presente = (nome) => status[nome].presente;
const criticos = [
  presente('content-security-policy'),
  !ehHttps || presente('strict-transport-security'),
  status['x-content-type-options'].valor.toLowerCase().trim() === 'nosniff',
  presente('x-frame-options') || temFrameAncestors,
].filter(Boolean).length;
const importantes = [presente('referrer-policy'), presente('permissions-policy')].filter(Boolean).length;
const temProblemaCSP = achados.some((a) => a.titulo.startsWith('CSP permite'));

let nota;
if (criticos === 4) {
  if (importantes === 2) nota = temProblemaCSP ? 'A-' : 'A+';
  else if (importantes === 1) nota = temProblemaCSP ? 'B+' : 'A-';
  else nota = temProblemaCSP ? 'B' : 'B+';
} else if (criticos === 3) nota = importantes >= 1 ? 'B' : 'C+';
else if (criticos === 2) nota = 'C';
else if (criticos === 1) nota = 'D';
else nota = 'F';

// Sem HTTPS a nota não passa de D.
const ORDEM = ['A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D', 'F'];
if (!ehHttps && ORDEM.indexOf(nota) < ORDEM.indexOf('D')) nota = 'D';

const ordemNivel = { alto: 0, medio: 1, baixo: 2, info: 3 };
achados.sort((a, b) => ordemNivel[a.nivel] - ordemNivel[b.nivel]);

return [{
  json: {
    auditoria: {
      urlOriginal: dados.urlOriginal,
      urlFinal: dados.urlFinal,
      host: dados.host,
      ips: dados.ips,
      status: dados.status,
      statusMessage: dados.statusMessage,
      cadeia: dados.cadeia,
      parouNoLimite: dados.parouNoLimite,
      conteudoTruncado: dados.conteudoTruncado,
      tamanhoConteudo: dados.tamanhoConteudo,
      dataHora: new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', dateStyle: 'long', timeStyle: 'short' }),
      ehHttps,
      nota,
      totalAlto: achados.filter((a) => a.nivel === 'alto').length,
      totalMedio: achados.filter((a) => a.nivel === 'medio').length,
      totalBaixo: achados.filter((a) => a.nivel === 'baixo').length,
      achados,
      statusCabecalhos: status,
      cabecalhos: cab,
      iaConfiguracao: textoDaIA('IA - configuração'),
      iaConteudo: textoDaIA('IA - conteúdo'),
    },
  },
}];
