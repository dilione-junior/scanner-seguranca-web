// Nó "Verificar DNS": confere para quais IPs o domínio aponta (consulta feita em dns.google).
// Se QUALQUER IP for interno ou reservado, o site não é acessado. Isso impede usar um domínio
// público que aponta para 127.0.0.1, 10.x, 172.16-31.x, 192.168.x etc. para alcançar a rede interna.
const alvo = $('Validar URL').last().json;
const respostaIPv4 = $('DNS (IPv4)').last().json;
const respostaIPv6 = $input.first().json;
// No modo "só reputação" o scanner não acessa o site: um domínio que não existe mais (phishing
// derrubado) ou que aponta para IP interno ainda pode ser consultado nas bases de reputação.
let soReputacao = false;
try { soReputacao = $('Configuração').first().json.modo === 'reputacao'; } catch (erro) { /* sem configuração */ }
const dnssec = respostaIPv4.AD === true;

if (alvo.ehIP) {
  return [{ json: { ...alvo, ok: true, ips: [alvo.host], dnssec: false } }];
}

const ips = [];
for (const resposta of [respostaIPv4, respostaIPv6]) {
  for (const registro of resposta.Answer ?? []) {
    // 1 = registro A (IPv4), 28 = registro AAAA (IPv6). CNAME (5) é só um apelido e é ignorado.
    if ((registro.type === 1 || registro.type === 28) && !ips.includes(registro.data)) ips.push(registro.data);
  }
}

if (soReputacao) {
  const avisoDns = ips.length === 0
    ? (respostaIPv4.Status === 3 ? 'O domínio não existe mais no DNS (NXDOMAIN).' : 'O domínio não resolveu para nenhum IP.')
    : ips.some(ipBloqueado) ? `O domínio aponta para IP interno ou reservado (${ips.filter(ipBloqueado).join(', ')}), comum em domínios suspensos ou "estacionados".` : '';
  return [{ json: { ...alvo, ok: true, ips: ips.filter((ip) => !ipBloqueado(ip)), dnssec, avisoDns } }];
}

if (ips.length === 0) {
  const naoExiste = respostaIPv4.Status === 3;
  return [{
    json: {
      ...alvo,
      ok: false,
      motivo: naoExiste
        ? `O domínio ${alvo.host} não existe. Confira se o endereço foi digitado corretamente.`
        : `Não foi possível descobrir o IP de ${alvo.host}. Tente novamente em alguns minutos.`,
    },
  }];
}

const bloqueados = ips.filter(ipBloqueado);
if (bloqueados.length > 0) {
  return [{
    json: {
      ...alvo,
      ok: false,
      motivo: `O domínio ${alvo.host} aponta para um endereço interno ou reservado (${bloqueados.join(', ')}). Por segurança, o scanner só analisa sites públicos.`,
    },
  }];
}

return [{ json: { ...alvo, ok: true, ips, dnssec } }];
