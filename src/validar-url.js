// Nó "Validar URL": confere o endereço ANTES de qualquer acesso.
// Aceita só http/https nas portas padrão e recusa nomes e IPs internos (proteção contra SSRF).
// Roda de novo a cada redirecionamento, porque um site público pode redirecionar para um endereço interno.
const entrada = $input.first().json;
const bruto = String(entrada.url ?? '').trim();
const saltos = Number(entrada.saltos ?? 0);
const urlOriginal = entrada.urlOriginal ?? bruto;
const cadeia = Array.isArray(entrada.cadeia) ? entrada.cadeia : [];

function falha(motivo) {
  return [{ json: { ok: false, motivo, url: bruto, urlOriginal, saltos, cadeia } }];
}

if (!bruto) return falha('Informe o endereço do site.');
if (bruto.length > 2048) return falha('O endereço é longo demais (máximo de 2048 caracteres).');

let url;
try {
  // Sem "http://" ou "https://", assume https.
  url = analisarUrl(/^[a-z][a-z0-9+.-]*:\/\//i.test(bruto) ? bruto : 'https://' + bruto);
} catch (erro) {
  if (!erro.ehErroDeUrl) throw erro;
  return falha(erro.message);
}

if (url.ehIP) {
  if (ipBloqueado(url.host)) {
    return falha(`O endereço ${url.host} é interno ou reservado. Por segurança, o scanner só analisa sites públicos.`);
  }
} else {
  const sufixosInternos = ['localhost', '.local', '.internal', '.intranet', '.lan', '.home', '.corp', '.home.arpa', '.localdomain', '.test', '.invalid', '.example'];
  if (!url.host.includes('.') || sufixosInternos.some((s) => url.host === s.replace(/^\./, '') || url.host.endsWith(s))) {
    return falha(`O nome "${url.host}" parece ser de uma rede interna. Por segurança, o scanner só analisa sites públicos com domínio completo (ex.: exemplo.com.br).`);
  }
}

return [{
  json: {
    ok: true,
    url: url.href,
    host: url.host,
    ehIP: url.ehIP,
    urlOriginal,
    saltos,
    cadeia,
  },
}];
