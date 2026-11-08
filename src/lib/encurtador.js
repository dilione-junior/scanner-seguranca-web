// ---- Biblioteca: encurtadores de link conhecidos ----
// Um link encurtado (bit.ly/abc) esconde o destino. A reputação do encurtador em si não diz nada:
// o que importa é para onde ele leva. Lista dos serviços mais usados (inclusive em phishing).
const ENCURTADORES = new Set([
  'bit.ly', 'bitly.com', 'bit.do', 'tinyurl.com', 't.co', 'goo.gl', 'g.co', 'ow.ly', 'buff.ly', 'is.gd', 'v.gd',
  'cutt.ly', 'rebrand.ly', 'rb.gy', 'shorturl.at', 't.ly', 'tiny.cc', 'tiny.one', 's.id', 'x.gd', 'lnkd.in',
  'shorte.st', 'adf.ly', 'bl.ink', 'short.io', 'shorturl.com', 'qrco.de', 'qr.io', 'urlz.fr', 'clck.ru',
  'u.to', 'soo.gd', 'gg.gg', '1url.com', 'chilp.it', 'trib.al', 'dlvr.it', 'ift.tt', 'linktr.ee', 'surl.li',
  'encurtador.com.br', 'encr.pw', 'abre.ai', 'l1nk.dev', 'tr.ee', 'msha.ke', 'forms.gle', 'han.gl', 'zpr.io',
  'aka.ms', 'amzn.to', 'youtu.be', 'wa.me', 'tinu.be', 'shrtco.de', '9qr.de', 'shre.ink', 'kutt.it', 'heylink.me',
]);

// "bit.ly", "www.bit.ly" ou "m.tinyurl.com" -> true
function ehEncurtador(host) {
  const h = String(host ?? '').toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  if (ENCURTADORES.has(h)) return true;
  const partes = h.split('.');
  return partes.length > 2 && ENCURTADORES.has(partes.slice(-2).join('.'));
}
