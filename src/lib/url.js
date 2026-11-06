// ---- Biblioteca: leitura ESTRITA de URLs ----
// O nó Code do n8n roda numa sandbox sem a classe URL, então a URL é lida aqui.
// A regra é "na dúvida, recusa": qualquer forma ambígua (IPv4 em octal/hexa/decimal, barra
// invertida, usuário@, caracteres não ASCII) é recusada. O endereço entregue ao nó "Buscar site"
// é remontado em formato canônico, para que o n8n acesse exatamente o host que foi validado.

const OCTETO = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_ESTRITO = new RegExp(`^${OCTETO}(\\.${OCTETO}){3}$`);
const ROTULO = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

function erroUrl(mensagem) {
  const erro = new Error(mensagem);
  erro.ehErroDeUrl = true;
  return erro;
}

// Devolve { protocolo, host, ehIP, porta, href } ou lança erro com mensagem amigável.
function analisarUrl(texto) {
  const bruto = String(texto ?? '').trim();
  if (/[\u0000-\u001f\u007f\s\\]/.test(bruto)) throw erroUrl('O endereço tem espaços, barra invertida ou caracteres de controle.');

  const partes = bruto.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/i);
  if (!partes) throw erroUrl('Endereço inválido. Exemplo de endereço válido: https://exemplo.com.br');
  const protocolo = partes[1].toLowerCase();
  const autoridade = partes[2];
  let resto = partes[3].replace(/#.*$/, '');

  if (protocolo !== 'http' && protocolo !== 'https') throw erroUrl('Só são aceitos endereços que começam com http:// ou https://.');
  if (autoridade.includes('@')) throw erroUrl('O endereço não pode conter usuário ou senha.');
  if (/[^\x21-\x7e]/.test(bruto)) throw erroUrl('Use apenas caracteres ASCII. Para domínios com acento, use a forma xn-- (punycode).');

  let host;
  let porta = '';
  const ipv6 = autoridade.match(/^\[([0-9a-f:.]+)\](?::(\d*))?$/i);
  if (ipv6) {
    if (!expandirIPv6(ipv6[1])) throw erroUrl('Endereço IPv6 inválido.');
    host = ipv6[1].toLowerCase();
    porta = ipv6[2] ?? '';
  } else {
    const comPorta = autoridade.match(/^([^:]*)(?::(\d*))?$/);
    if (!comPorta) throw erroUrl('Endereço inválido.');
    host = comPorta[1].toLowerCase().replace(/\.$/, '');
    porta = comPorta[2] ?? '';
  }
  if (!host) throw erroUrl('O endereço não tem domínio.');

  const portaPadrao = protocolo === 'https' ? '443' : '80';
  porta = porta.replace(/^0+(?=\d)/, '');
  if (porta === portaPadrao) porta = '';
  if (porta && !['80', '443'].includes(porta)) throw erroUrl(`A porta ${porta} não é permitida. O scanner só analisa sites nas portas 80 e 443.`);

  let ehIP = Boolean(ipv6);
  if (!ipv6) {
    const rotulos = host.split('.');
    const ultimo = rotulos[rotulos.length - 1];
    // Como no navegador: se o último pedaço for numérico, o host é tratado como IPv4.
    if (/^(0x[0-9a-f]*|\d+)$/i.test(ultimo)) {
      if (!IPV4_ESTRITO.test(host)) throw erroUrl(`"${host}" não é um IPv4 válido no formato a.b.c.d (sem zeros à esquerda).`);
      ehIP = true;
    } else {
      if (host.length > 253 || !rotulos.every((r) => ROTULO.test(r))) throw erroUrl(`"${host}" não é um nome de domínio válido.`);
    }
  }

  if (!resto.startsWith('/')) resto = '/' + resto;
  resto = resto.replace(/[^A-Za-z0-9\-._~:/?\[\]@!$&'()*+,;=%]/g, (c) => encodeURIComponent(c));

  const hostNaUrl = ipv6 ? `[${host}]` : host;
  return { protocolo, host, ehIP, porta, href: `${protocolo}://${hostNaUrl}${porta ? ':' + porta : ''}${resto}` };
}

// Resolve o cabeçalho Location de um redirecionamento em relação à página atual (base canônica).
// Formas estranhas são devolvidas como estão: a validação seguinte as recusa.
function resolverUrl(destino, base) {
  const d = String(destino ?? '').trim();
  const origem = base.match(/^(https?:\/\/[^/?#]+)/i)[1];
  const caminhoBase = base.slice(origem.length).replace(/[?#].*$/, '') || '/';
  if (/^[a-z][a-z0-9+.-]*:/i.test(d)) return d;
  if (d.startsWith('\\') || d.startsWith('/\\')) return d;
  if (d.startsWith('//')) return base.split(':')[0] + ':' + d;
  if (d.startsWith('/')) return origem + d;
  if (d.startsWith('?')) return origem + caminhoBase + d;
  if (d.startsWith('#') || d === '') return base;
  return origem + caminhoBase.replace(/[^/]*$/, '') + d;
}
// ---- fim da biblioteca ----
