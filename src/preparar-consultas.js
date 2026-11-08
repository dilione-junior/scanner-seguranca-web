// Nó "Preparar consultas": ponto único de onde partem as consultas de inteligência.
// Recebe a página final (de "Tratar resposta") ou o alvo sem visita (modo "só reputação")
// e calcula o que cada fonte precisa: domínio registrado, IP principal, ID da URL no VirusTotal.
// As fontes são só CONSULTADAS: nenhuma URL é enviada para análise pública.
const pagina = $input.first().json;
const config = $('Configuração').first().json;
const host = String(pagina.host ?? '').toLowerCase();
const ehIP = ehIPv4(host) || host.includes(':');
const dominio = ehIP ? host : dominioRegistravel(host);
const ips = Array.isArray(pagina.ips) ? pagina.ips : [];
const ipPrincipal = ips.find(ehIPv4) ?? ips[0] ?? '';
// Porta fora do padrão (ex.: http://1.2.3.4:45634/i). Vazio = 80/443.
let porta = '';
try { porta = analisarUrl(pagina.urlFinal).porta; } catch (erro) { /* URL já validada antes */ }

// Hosts diferentes que apareceram nos redirecionamentos (encurtadores, rastreadores, cadeias de phishing).
const hostsCadeia = [];
for (const passo of pagina.cadeia ?? []) {
  const h = String(passo.url ?? '').match(/^https?:\/\/([^/:?#]+)/i)?.[1]?.toLowerCase();
  if (h && h !== host && !hostsCadeia.includes(h)) hostsCadeia.push(h);
}

return [{
  json: {
    ...pagina,
    modo: config.modo,
    contexto: config.contexto ?? '',
    ehIP,
    dominio,
    ipPrincipal,
    porta,
    hostsCadeia,
    vtUrlId: base64Url(pagina.urlFinal),
    vtEntidade: ehIP ? `ip_addresses/${encodeURIComponent(host)}` : `domains/${encodeURIComponent(dominio)}`,
    rdap: ehIP ? `ip/${encodeURIComponent(host)}` : `domain/${encodeURIComponent(dominio)}`,
    // O Observatory só testa as portas 80/443: com outra porta, avaliaria outro serviço.
    observatorio: Boolean(pagina.visitado) && !ehIP && !porta,
    // urlscan.io: análise nova só no modo completo (o navegador do urlscan abre o site).
    // Nunca "public": só "private" (padrão) ou "unlisted".
    urlscanAnalisar: Boolean(pagina.visitado),
    urlscanVisibilidade: config.urlscanVisibilidade === 'unlisted' ? 'unlisted' : 'private',
    // Cache por URL e por modo (o modo completo guarda a análise privada do urlscan; o outro, não).
    chaveCache: `${config.prefixoCache || 'scanner:'}intel:${config.modo === 'completa' ? 'completa' : 'reputacao'}:${base64Url(pagina.urlFinal)}`,
  },
}];
