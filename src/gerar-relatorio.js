// Nó "Gerar relatório": monta o relatório em HTML (o mesmo para a tela e para o e-mail).
// Só usa estilos inline, que funcionam no Outlook e dentro da página do formulário.
// Ordem pensada para o analista SOC: parecer e ações primeiro, evidências depois, detalhes no fim.
const a = $input.first().json.auditoria;
const p = a.parecer;
const intel = a.inteligencia;
const f = intel.fontes;

const CORES_NOTA = { 'A+': '#15803d', A: '#15803d', 'A-': '#15803d', 'B+': '#1d4ed8', B: '#1d4ed8', 'B-': '#1d4ed8', 'C+': '#b45309', C: '#b45309', 'C-': '#b45309', D: '#b91c1c', F: '#b91c1c', 'N/A': '#64748b' };
const VEREDITOS = {
  malicioso: { rotulo: 'MALICIOSO', cor: '#b91c1c', fundo: '#fef2f2' },
  suspeito: { rotulo: 'SUSPEITO', cor: '#b45309', fundo: '#fffbeb' },
  indeterminado: { rotulo: 'INDETERMINADO', cor: '#475569', fundo: '#f8fafc' },
  limpo: { rotulo: 'SEM AMEAÇA CONHECIDA', cor: '#15803d', fundo: '#f0fdf4' },
};
const NIVEIS = {
  alto: { rotulo: 'Alto', cor: '#b91c1c', fundo: '#fef2f2' },
  medio: { rotulo: 'Médio', cor: '#b45309', fundo: '#fffbeb' },
  baixo: { rotulo: 'Baixo', cor: '#1d4ed8', fundo: '#eff6ff' },
  info: { rotulo: 'Info', cor: '#475569', fundo: '#f8fafc' },
  malicioso: { rotulo: 'Malicioso', cor: '#b91c1c', fundo: '#fef2f2' },
  suspeito: { rotulo: 'Suspeito', cor: '#b45309', fundo: '#fffbeb' },
};
const NOMES_CABECALHOS = {
  'content-security-policy': 'Content-Security-Policy',
  'strict-transport-security': 'Strict-Transport-Security',
  'x-content-type-options': 'X-Content-Type-Options',
  'x-frame-options': 'X-Frame-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
  'cross-origin-opener-policy': 'Cross-Origin-Opener-Policy',
  'cross-origin-embedder-policy': 'Cross-Origin-Embedder-Policy',
  'cross-origin-resource-policy': 'Cross-Origin-Resource-Policy',
  'x-permitted-cross-domain-policies': 'X-Permitted-Cross-Domain-Policies',
};
const v = VEREDITOS[p.veredito] ?? VEREDITOS.indeterminado;
// Por dentro a nota é de SEGURANÇA (100 = seguro). Para o analista mostramos o RISCO (100 = máximo),
// que é o jeito comum de ler em SOC: site malicioso aparece com risco alto, não com "nota 0".
const risco = (nota) => 100 - Math.max(0, Math.min(100, Math.round(Number(nota) || 0)));
const riscoFinal = risco(p.nota);
const NIVEL_RISCO = riscoFinal >= 70 ? 'crítico/alto' : riscoFinal >= 40 ? 'moderado' : riscoFinal >= 20 ? 'baixo' : 'mínimo';
const corNota = riscoFinal >= 60 ? '#b91c1c' : riscoFinal >= 40 ? '#b45309' : riscoFinal >= 20 ? '#1d4ed8' : '#15803d';
const maiuscula = (t) => { const x = String(t ?? ''); return x.charAt(0).toUpperCase() + x.slice(1); };

// Detecções por fonte, em frases curtas: usadas no parecer (tela/e-mail) e no texto para copiar.
function deteccoes() {
  const d = [];
  const add = (fonte, alerta, texto) => d.push({ fonte, alerta: Boolean(alerta), texto });
  const motores = (x) => x.malicioso + x.suspeito + x.inofensivo + (x.naoDetectado ?? 0);
  if (f.vtUrl?.naoVista) add('VirusTotal (URL)', false, 'URL nunca analisada');
  else if (f.vtUrl) add('VirusTotal (URL)', f.vtUrl.malicioso > 0, `${f.vtUrl.malicioso} de ${motores(f.vtUrl)} motores: malicioso${f.vtUrl.suspeito ? `; ${f.vtUrl.suspeito} suspeito` : ''}`);
  if (f.vtDominio) add(`VirusTotal (${a.ehIP ? 'IP' : 'domínio'})`, f.vtDominio.malicioso > 0, `${f.vtDominio.malicioso} de ${motores(f.vtDominio)} motores: malicioso${f.vtDominio.suspeito ? `; ${f.vtDominio.suspeito} suspeito` : ''} · reputação ${f.vtDominio.reputacao}`);
  if (f.urlhaus) add('URLhaus', f.urlhaus.exata || f.urlhaus.online > 0, f.urlhaus.exata
    ? `URL listada (${f.urlhaus.exata.ameaca}, ${f.urlhaus.exata.status}) · ${f.urlhaus.totalUrls} URL(s) do host, ${f.urlhaus.online} online`
    : f.urlhaus.listado ? `${f.urlhaus.totalUrls} URL(s) do host listadas, ${f.urlhaus.online} online` : 'sem registro');
  if (f.threatfox) add('ThreatFox', f.threatfox.exatos.length > 0, f.threatfox.exatos.length
    ? f.threatfox.exatos.map((x) => `${x.malware} (${x.tipo}, confiança ${x.confianca}%)`).join('; ')
    : f.threatfox.total ? `${f.threatfox.total} IOC(s) no host (não o endereço exato)` : 'nenhum IOC');
  if (f.abuseipdb) add('AbuseIPDB', f.abuseipdb.pontuacao >= 50, `${f.abuseipdb.pontuacao}% de confiança de abuso, ${f.abuseipdb.denuncias} denúncia(s) · ${f.abuseipdb.provedor} (${f.abuseipdb.pais})`);
  if (f.otx) add('OTX AlienVault', !f.otx.confiavel && f.otx.pulsos > 0, `${f.otx.pulsos} relatório(s) de ameaça${f.otx.confiavel ? ' (domínio confiável, desconsiderados)' : ''}`);
  const lr = f.linkRelacionado;
  if (lr?.vt) add(`VirusTotal (${lr.rotulo})`, lr.vt.malicioso > 0, lr.vt.naoVista ? `${lr.rotulo} nunca analisado` : `${lr.vt.malicioso} de ${motores(lr.vt)} motores: malicioso${lr.vt.suspeito ? `; ${lr.vt.suspeito} suspeito` : ''}`);
  if (lr?.urlhaus) add(`URLhaus (${lr.rotulo})`, lr.urlhaus.listada, lr.urlhaus.listada ? `listado (${lr.urlhaus.ameaca}, ${lr.urlhaus.status})` : 'sem registro');
  if (f.urlscan?.analise) {
    const an = f.urlscan.analise;
    const h = f.urlscan.historico;
    add('urlscan.io', an.malicioso || an.marcas.length > 0, `${an.malicioso ? 'página maliciosa' : 'sem veredito malicioso'} (pontuação ${an.pontuacao})${an.marcas.length ? ` · imita ${an.marcas.join(', ')}` : ''} · ${h.total} análise(s) do host${h.tags.length ? ` · tags (não verificadas): ${h.tags.join(', ')}` : ''}`);
  }
  return d;
}
const listaDeteccoes = deteccoes();
const fontesComAlerta = listaDeteccoes.filter((x) => x.alerta).length;

const caixa = (titulo, conteudo) => `
  <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:16px 18px;margin:0 0 16px">
    <h2 style="font-size:18px;color:#0f172a;margin:0 0 12px">${titulo}</h2>
    ${conteudo}
  </div>`;
const etiqueta = (texto, cor) => `<span style="display:inline-block;font-size:11px;font-weight:bold;color:#fff;background:${cor};padding:2px 6px;border-radius:3px;margin-right:6px">${escapar(texto)}</span>`;
const itens = (lista) => (lista.length ? `<ul style="margin:4px 0 0;padding-left:22px">${lista.map((x) => `<li style="margin:3px 0">${escapar(x)}</li>`).join('')}</ul>` : '');
const linha = (rotulo, valor) => `<tr><td style="padding:3px 10px 3px 0;color:#475569;vertical-align:top;white-space:nowrap">${rotulo}</td><td style="padding:3px 0;word-break:break-word">${valor}</td></tr>`;
const pre = (texto) => `<pre style="background:#0f172a;color:#e2e8f0;padding:10px 12px;border-radius:6px;margin:4px 0 0;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all">${escapar(texto)}</pre>`;

// ---------------- Parecer ----------------
function blocoParecer() {
  const sub = (titulo, conteudo) => (conteudo ? `<div style="margin-top:12px"><strong style="color:#0f172a">${titulo}</strong>${conteudo}</div>` : '');
  return `
    <table style="width:100%;border-collapse:collapse"><tr>
      <td style="width:120px;vertical-align:top;padding-right:14px;text-align:center">
        <div style="width:104px;height:104px;border-radius:52px;border:8px solid ${corNota};box-sizing:border-box;line-height:88px;font-size:38px;font-weight:bold;color:${corNota}">${escapar(riscoFinal)}</div>
        <div style="font-size:12px;color:#475569;margin-top:4px">risco de 0 a 100<br>(100 = máximo)</div>
      </td>
      <td style="vertical-align:top;font-size:14px">
        <div style="display:inline-block;padding:6px 12px;border-radius:6px;background:${v.cor};color:#fff;font-weight:bold;font-size:16px">${v.rotulo}</div>
        ${p.classificacao ? `<span style="margin-left:8px;color:#334155">${escapar(p.classificacao)}</span>` : ''}
        <table style="border-collapse:collapse;margin-top:10px">
          ${linha('Risco:', `<strong style="color:${corNota}">${escapar(riscoFinal)}/100 (${escapar(NIVEL_RISCO)})</strong>`)}
          ${linha('Detecções:', `${escapar(fontesComAlerta)} de ${escapar(listaDeteccoes.length)} fonte(s) com alerta`)}
          ${linha('Gravidade:', escapar(p.gravidade))}
          ${linha('Confiança:', escapar(p.confianca))}
          ${linha('Parecer por:', p.origem === 'ia' ? 'IA analista SOC (Gemini), com travas automáticas' : '<span style="color:#b45309">regras automáticas (IA indisponível)</span>')}
          ${linha('Base automática:', `${escapar(intel.vereditoAutomatico)}, risco ${escapar(risco(intel.notaAutomatica))}/100, ${escapar(intel.fontesReputacao)} fonte(s) de reputação`)}
        </table>
      </td>
    </tr></table>
    <p style="margin:12px 0 0;color:#0f172a;line-height:1.5">${escapar(p.resumo)}</p>
    ${p.avisos.map((x) => `<p style="margin:8px 0 0;padding:8px 10px;background:#fffbeb;border-left:4px solid #b45309;color:#78350f;font-size:13px">⚠ ${escapar(x)}</p>`).join('')}
    ${sub('Evidências', itens(p.evidencias))}
    ${sub('Possíveis falsos positivos', p.falsosPositivos ? `<p style="margin:4px 0 0">${escapar(p.falsosPositivos)}</p>` : '')}
    ${sub('Ações recomendadas para o SOC', itens(p.acoes))}
    ${sub('Correções para o responsável pelo site', itens(p.correcoes))}
    ${sub('MITRE ATT&amp;CK', itens(p.mitre))}`;
}

// ---------------- Inteligência ----------------
function blocoInteligencia() {
  const lk = (url, texto = 'abrir') => (url ? ` · ${linkSeguro(url).replace(/>https?:[^<]*</, `>${texto}<`)}` : '');
  const linhas = [];
  const add = (fonte, texto) => linhas.push(`<tr><td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-weight:bold;white-space:nowrap;vertical-align:top">${fonte}</td><td style="padding:6px 8px;border-bottom:1px solid #e2e8f0">${texto}</td></tr>`);
  if (f.urlscan) {
    const u = f.urlscan;
    const an = u.analise;
    const partes = [];
    if (an) {
      partes.push(`${an.malicioso ? '<strong style="color:#b91c1c">página classificada como maliciosa</strong>' : 'sem veredito malicioso'} (pontuação ${escapar(an.pontuacao)}) · ${an.propria ? `análise feita agora (${escapar(an.visibilidade)})` : `análise anterior de ${escapar(an.data)}`}`);
      if (an.marcas.length) partes.push(`<span style="color:#b91c1c">Marca imitada: ${escapar(an.marcas.join(', '))}</span>`);
      if (an.titulo) partes.push(`Título: ${escapar(an.titulo)}`);
      partes.push(`Contatou ${escapar(an.totalDominios)} domínio(s) e ${escapar(an.totalIps)} IP(s)${an.paises.length ? ` em ${escapar(an.paises.join(', '))}` : ''}${an.dominiosContatados.length ? `: ${escapar(an.dominiosContatados.slice(0, 8).map(desarmar).join(', '))}${an.totalDominios > 8 ? '...' : ''}` : ''}`);
      partes.push(`${lk(an.link, 'abrir análise').replace(/^ · /, '')}${lk(an.print, 'print da página')}${an.visibilidade === 'private' ? ' <span style="color:#64748b">(privada: abre logado na sua conta)</span>' : ''}`);
    } else partes.push('Nenhuma análise disponível.');
    if (u.erroEnvio) partes.push(`<span style="color:#b45309">Análise nova: ${escapar(u.erroEnvio)}</span>${lk(u.linkPendente, 'ver depois')}`);
    partes.push(`Histórico: ${u.historico.total >= 10000 ? 'mais de 10.000' : escapar(u.historico.total)} análise(s) do host${u.historico.tags.length ? ` · tags (não verificadas): ${escapar(u.historico.tags.join(', '))}` : ''}`);
    add('urlscan.io', partes.join('<br>'));
  }
  if (f.vtUrl) add('VirusTotal (URL)', f.vtUrl.naoVista ? 'URL nunca analisada (não foi enviada: o scanner só consulta).'
    : `${f.vtUrl.malicioso} malicioso · ${f.vtUrl.suspeito} suspeito · ${f.vtUrl.inofensivo} inofensivo${f.vtUrl.ultimaAnalise ? ` (análise de ${escapar(f.vtUrl.ultimaAnalise)})` : ''}${f.vtUrl.motores.length ? `<br><span style="color:#b91c1c">${escapar(f.vtUrl.motores.join('; '))}</span>` : ''}${lk(f.vtUrl.link)}`);
  if (f.vtDominio) add(`VirusTotal (${a.ehIP ? 'IP' : 'domínio'})`, `${f.vtDominio.malicioso} malicioso · ${f.vtDominio.suspeito} suspeito · reputação ${escapar(f.vtDominio.reputacao)}${f.vtDominio.melhorRank ? ` · ranking ${escapar(f.vtDominio.fonteRank)} #${escapar(f.vtDominio.melhorRank)}` : ''}${f.vtDominio.categorias.length ? `<br>Categorias: ${escapar(f.vtDominio.categorias.join(', '))}` : ''}${f.vtDominio.motores.length ? `<br><span style="color:#b91c1c">${escapar(f.vtDominio.motores.join('; '))}</span>` : ''}${lk(f.vtDominio.link)}`);
  if (f.urlhaus) add('URLhaus', !f.urlhaus.listado ? 'Host sem registro de distribuição de malware.'
    : `${f.urlhaus.exata ? `<strong style="color:#b91c1c">URL listada (${escapar(f.urlhaus.exata.ameaca)}, ${escapar(f.urlhaus.exata.status)})</strong> · ` : ''}${escapar(f.urlhaus.totalUrls)} URL(s) do host já listadas, ${escapar(f.urlhaus.online)} online${f.urlhaus.ameacas.length ? ` (${escapar(f.urlhaus.ameacas.join(', '))})` : ''} · Spamhaus DBL: ${escapar(f.urlhaus.spamhausDbl)}${lk(f.urlhaus.link)}`);
  if (f.threatfox) add('ThreatFox', f.threatfox.exatos.length ? `<strong style="color:#b91c1c">${escapar(f.threatfox.exatos.map((x) => `${x.malware} (${x.tipo}, confiança ${x.confianca})`).join('; '))}</strong>`
    : f.threatfox.total ? `${escapar(f.threatfox.total)} IOC(s) em URLs deste host (não é o endereço exato).` : 'Nenhum IOC.');
  if (f.otx) add('OTX AlienVault', `${escapar(f.otx.pulsos)} relatório(s) de ameaça${f.otx.confiavel ? ' · domínio em lista de confiáveis (pulsos desconsiderados)' : ''}`);
  if (f.abuseipdb) add('AbuseIPDB', `IP ${escapar(f.abuseipdb.ip)}: ${escapar(f.abuseipdb.pontuacao)}% de confiança de abuso, ${escapar(f.abuseipdb.denuncias)} denúncia(s) · ${escapar(f.abuseipdb.uso)} · ${escapar(f.abuseipdb.provedor)} (${escapar(f.abuseipdb.pais)})${f.abuseipdb.tor ? ' · <strong>Tor</strong>' : ''}`);
  const lr = f.linkRelacionado;
  if (lr?.vt) add(`VirusTotal (${escapar(lr.rotulo)})`, lr.vt.naoVista ? `${escapar(desarmar(lr.url))}: nunca analisado.`
    : `${escapar(desarmar(lr.url))}<br>${lr.vt.malicioso} malicioso · ${lr.vt.suspeito} suspeito · ${lr.vt.inofensivo} inofensivo${lr.vt.ultimaAnalise ? ` (análise de ${escapar(lr.vt.ultimaAnalise)})` : ''}${lr.vt.motores.length ? `<br><span style="color:#b91c1c">${escapar(lr.vt.motores.join('; '))}</span>` : ''}${lk(lr.vt.link)}`);
  if (lr?.urlhaus) add(`URLhaus (${escapar(lr.rotulo)})`, lr.urlhaus.listada ? `<strong style="color:#b91c1c">listado (${escapar(lr.urlhaus.ameaca)}, ${escapar(lr.urlhaus.status)})</strong>${lk(lr.urlhaus.link)}` : 'sem registro');
  if (!linhas.length) return '<p style="margin:0;color:#b45309">Nenhuma fonte de reputação respondeu.</p>';
  const falhas = intel.falharam.length ? `<p style="margin:8px 0 0;color:#b45309;font-size:13px">Fontes que não responderam: ${escapar(intel.falharam.join('; '))}</p>` : '';
  return `<table style="width:100%;border-collapse:collapse;font-size:13px">${linhas.join('')}</table>${falhas}`;
}

function blocoSinais() {
  if (!intel.sinais.length) return '<p style="margin:0">Nenhum sinal de risco nas fontes consultadas.</p>';
  return intel.sinais.map((s) => {
    const n = NIVEIS[s.nivel] ?? NIVEIS.info;
    return `<div style="border-left:4px solid ${n.cor};background:${n.fundo};padding:8px 10px;margin:0 0 8px;border-radius:0 6px 6px 0;font-size:13px">${etiqueta(n.rotulo, n.cor)}<strong>${escapar(s.fonte)}:</strong> ${escapar(s.texto)} <span style="color:#64748b">(+${escapar(s.pontos)} de risco)</span></div>`;
  }).join('');
}

function blocoDominio() {
  const r = f.registro;
  const d = f.dnsEmail;
  const vt = f.vtDominio;
  const s = f.internetdb;
  const linhas = [];
  if (r) linhas.push(linha('Registrado em:', `${escapar(r.criadoEm || 'desconhecido')}${r.idadeDias !== null ? ` (${escapar(r.idadeDias)} dias)` : ''}${r.registrador ? ` · ${escapar(r.registrador)}` : ''}${r.expiraEm ? ` · expira em ${escapar(r.expiraEm)}` : ''}`));
  if (vt?.certEmissor || vt?.certValidoAte) linhas.push(linha('Certificado:', `${escapar(vt.certEmissor)}${vt.certValidoAte ? ` · válido até ${escapar(vt.certValidoAte)} (${escapar(vt.certDiasRestantes)} dias)` : ''} <span style="color:#64748b">(último visto pelo VirusTotal)</span>`));
  if (vt?.asn) linhas.push(linha('Rede:', `${escapar(vt.asn)}${vt.pais ? ` · ${escapar(vt.pais)}` : ''}`));
  if (d) {
    linhas.push(linha('SPF:', d.spf ? `<code>${escapar(d.spf)}</code>` : '<span style="color:#b45309">ausente</span>'));
    linhas.push(linha('DMARC:', d.dmarc ? `<code>${escapar(d.dmarc)}</code>` : '<span style="color:#b45309">ausente</span>'));
    linhas.push(linha('DNSSEC:', d.dnssec ? 'ativo' : 'não validado'));
  }
  if (s) linhas.push(linha('Portas (Shodan):', s.semDados ? 'sem dados no Shodan' : `${escapar(s.portas.join(', ') || 'nenhuma')}${s.portasRisco.length ? ` · <span style="color:#b91c1c">sensíveis: ${escapar(s.portasRisco.join(', '))}</span>` : ''}${s.totalCves ? `<br>CVEs associadas: ${escapar(s.cves.join(', '))}${s.totalCves > s.cves.length ? ` (+${s.totalCves - s.cves.length})` : ''}` : ''}${s.tags.length ? `<br>Tags: ${escapar(s.tags.join(', '))}` : ''}`));
  if (f.observatory) linhas.push(linha('Mozilla Observatory:', `nota ${escapar(f.observatory.nota)} (${escapar(f.observatory.pontos)} pontos, ${escapar(f.observatory.testesFalhos)} de ${escapar(f.observatory.testesTotal)} testes falharam) · ${linkSeguro(f.observatory.link).replace(/>https?:[^<]*</, '>abrir<')}`));
  if (!linhas.length) return '';
  return caixa('Domínio, DNS e infraestrutura', `<table style="border-collapse:collapse;font-size:13px">${linhas.join('')}</table>`);
}

// ---------------- IOCs e texto para chamado ----------------
// Texto puro, com seções numeradas: cola igual no Teams, no e-mail e no chamado (GLPI ou outro).
// Tudo que aponta para o alvo sai desarmado (hxxp, [.]).
const tipoIoc = (x) => (/^[a-z][a-z0-9+.-]*:\/\//i.test(x) ? 'URL' : /^[\d.]+$|:/.test(x) ? 'IP' : 'Domínio');
const rel = f.linkRelacionado;
const iocs = [...new Set([a.urlOriginal, a.urlFinal, rel?.url, a.host, a.dominio, rel?.host, ...(a.ips ?? []), ...(a.hostsCadeia ?? [])].filter(Boolean))]
  .map((valor) => ({ tipo: tipoIoc(valor), valor: desarmar(valor) }));
const ACAO_POR_VEREDITO = {
  malicioso: 'BLOQUEAR (após aprovação do responsável)',
  suspeito: 'INVESTIGAR antes de liberar',
  indeterminado: 'INVESTIGAR: fontes insuficientes',
  limpo: 'Sem ação de bloqueio: nenhuma ameaça conhecida',
};
let numeroSecao = 0;
const secao = (titulo, linhas) => (linhas.length ? [`${++numeroSecao}. ${titulo}`, ...linhas, ''] : []);
const marcadores = (lista) => lista.map((x) => `- ${x}`);
const textoChamado = [
  `[SOC] Parecer de análise de URL - ${p.veredito.toUpperCase()}`,
  `Data: ${a.dataHora} | Modo: ${a.visitado ? 'completo (página lida uma vez)' : 'só reputação (site não acessado)'}`,
  '',
  ...secao('RESUMO DO PARECER', [
    `Veredito: ${p.veredito.toUpperCase()}${p.classificacao ? ` - ${p.classificacao}` : ''}`,
    `Risco: ${riscoFinal}/100 (${NIVEL_RISCO}) | Gravidade: ${maiuscula(p.gravidade)} | Confiança: ${maiuscula(p.confianca)}`,
    `Detecções: ${fontesComAlerta} de ${listaDeteccoes.length} fonte(s) com alerta`,
    `Ação sugerida: ${ACAO_POR_VEREDITO[p.veredito] ?? ACAO_POR_VEREDITO.indeterminado}`,
  ]),
  ...secao('ALVO', [
    `URL: ${desarmar(a.urlOriginal)}`,
    ...(a.urlFinal !== a.urlOriginal ? [`Página final: ${desarmar(a.urlFinal)}`] : []),
    ...(rel?.encurtador ? [`Link encurtado: sim (${rel.encurtador})`] : []),
    ...(rel?.papel === 'destino' ? [`Destino conhecido (VirusTotal): ${desarmar(rel.url)}`] : []),
    ...(rel?.destinoDesconhecido ? ['Destino: desconhecido (o encurtador não foi aberto)'] : []),
    `IP: ${(a.ips ?? []).map(desarmar).join(', ') || 'nenhum'}${f.abuseipdb ? ` (${f.abuseipdb.provedor}, ${f.abuseipdb.pais})` : ''}`,
    ...(a.contexto ? [`Contexto informado: ${a.contexto}`] : []),
  ]),
  ...secao('ANÁLISE', [p.resumo]),
  ...secao('DETECÇÕES NAS FONTES', listaDeteccoes.map((x) => `- ${x.alerta ? '[ALERTA] ' : ''}${x.fonte}: ${x.texto}`)),
  ...secao('EVIDÊNCIAS', marcadores(p.evidencias)),
  ...secao('AÇÕES RECOMENDADAS', [...marcadores(p.acoes), ...(p.acoes.length ? ['Obs.: bloqueio e isolamento só com aprovação humana.'] : [])]),
  ...secao('MITRE ATT&CK', marcadores(p.mitre)),
  ...secao('IOCs (desarmados)', iocs.map((x) => `- ${x.tipo}: ${x.valor}`)),
  ...secao('FONTES CONSULTADAS', [intel.consultadas.join(', ') || 'nenhuma']),
  'Gerado pelo Scanner de Segurança Web. Confirme as evidências antes de bloquear ou liberar.',
].join('\n');

function blocoIocs() {
  const cor = (tipo) => (tipo === 'URL' ? '#b91c1c' : tipo === 'IP' ? '#7c3aed' : '#1d4ed8');
  const tabela = `<table style="width:100%;border-collapse:collapse;font-size:13px;margin:0 0 14px">
    <tr><th style="text-align:left;padding:6px 8px;background:#f1f5f9;border-bottom:1px solid #cbd5e1;width:90px">Tipo</th><th style="text-align:left;padding:6px 8px;background:#f1f5f9;border-bottom:1px solid #cbd5e1">Indicador (desarmado)</th></tr>
    ${iocs.map((x) => `<tr><td style="padding:6px 8px;border-bottom:1px solid #e2e8f0">${etiqueta(x.tipo, cor(x.tipo))}</td><td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-family:Consolas,monospace;word-break:break-all">${escapar(x.valor)}</td></tr>`).join('')}
  </table>`;
  const texto = `<div style="font-size:13px;color:#475569;margin:0 0 6px"><strong style="color:#0f172a">Parecer pronto para copiar</strong> (Teams, e-mail ou chamado): selecione o texto do quadro abaixo e copie. Os endereços já estão desarmados.</div>
    <pre style="background:#f8fafc;color:#0f172a;border:1px solid #cbd5e1;border-left:4px solid ${v.cor};padding:12px 14px;border-radius:6px;margin:0;font-family:Consolas,'Courier New',monospace;font-size:12.5px;line-height:1.5;white-space:pre-wrap;word-break:break-word">${escapar(textoChamado)}</pre>`;
  return tabela + texto;
}

// ---------------- Postura ----------------
function selos() {
  return Object.entries(NOMES_CABECALHOS).slice(0, 6).map(([chave, nome]) => {
    const ok = a.statusCabecalhos[chave]?.presente;
    return `<span style="display:inline-block;margin:2px 4px 2px 0;padding:3px 8px;border-radius:4px;font-size:12px;color:#fff;background:${ok ? '#15803d' : '#b91c1c'}">${ok ? '✓' : '✗'} ${escapar(nome)}</span>`;
  }).join('');
}

function listaAchados() {
  if (!a.achados.length) return '<p style="margin:0">Nenhum problema encontrado nos cabeçalhos e cookies.</p>';
  return a.achados.map((x) => {
    const n = NIVEIS[x.nivel];
    return `
      <div style="border-left:4px solid ${n.cor};background:${n.fundo};padding:10px 12px;margin:0 0 10px;border-radius:0 6px 6px 0">
        <div>${etiqueta(n.rotulo, n.cor)}<strong style="color:#0f172a">${escapar(x.titulo)}</strong></div>
        <div style="margin-top:6px;color:#334155">${escapar(x.detalhe)}</div>
        ${x.correcao ? `<div style="margin-top:6px"><span style="color:#475569;font-size:13px">Como corrigir:</span>${pre(x.correcao)}</div>` : ''}
      </div>`;
  }).join('');
}

function blocoPostura() {
  if (!a.visitado) return caixa('Postura de segurança', '<p style="margin:0;color:#475569">Não avaliada: no modo <strong>só reputação</strong> o scanner não acessa o site.</p>');
  return caixa(`Postura de segurança: nota ${escapar(a.nota)}`, `
    <table style="width:100%;border-collapse:collapse"><tr>
      <td style="width:76px;vertical-align:top;padding-right:12px"><div style="width:64px;height:64px;line-height:64px;text-align:center;font-size:28px;font-weight:bold;color:#fff;border-radius:8px;background:${CORES_NOTA[a.nota] ?? '#b91c1c'}">${escapar(a.nota)}</div></td>
      <td style="vertical-align:top;font-size:13px;color:#334155">Nota dos cabeçalhos de segurança, calculada por regras sobre a resposta real (não pela IA).<br>
        <strong style="color:#b91c1c">${a.totalAlto} alto</strong> · <strong style="color:#b45309">${a.totalMedio} médio</strong> · <strong style="color:#1d4ed8">${a.totalBaixo} baixo</strong>
        <div style="margin-top:8px">${selos()}</div></td>
    </tr></table>
    <div style="margin-top:12px">${listaAchados()}</div>`);
}

function analiseIA(resultado) {
  if (!resultado?.ok) return `<p style="margin:0;color:#b45309">${escapar(resultado?.texto ?? 'Não executada.')}</p>`;
  return `<div style="color:#334155;font-size:14px;line-height:1.5">${markdownParaHtml(resultado.texto)}</div>`;
}

function tabelaCabecalhos() {
  const linhas = Object.entries(a.cabecalhos).flatMap(([nome, valor]) =>
    (Array.isArray(valor) ? valor : [valor]).map((x) => `
      <tr>
        <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-weight:bold;vertical-align:top;white-space:nowrap;color:${NOMES_CABECALHOS[nome] ? '#15803d' : '#0f172a'}">${escapar(nome)}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-family:Consolas,monospace;font-size:12px;word-break:break-all">${escapar(x)}</td>
      </tr>`));
  if (!linhas.length) return '<p style="margin:0">Nenhum cabeçalho recebido.</p>';
  return `<table style="width:100%;border-collapse:collapse;font-size:13px">${linhas.join('')}</table>`;
}

function cadeiaRedirecionamentos() {
  if (!a.cadeia || a.cadeia.length <= 1) return '';
  const lista = a.cadeia.map((c) => `<li style="margin:3px 0"><code>${escapar(c.status)}</code> ${escapar(desarmar(c.url))}</li>`).join('');
  const aviso = a.parouNoLimite ? '<p style="margin:8px 0 0;color:#b45309">O site ainda pedia outro redirecionamento; o scanner parou no limite de 5.</p>' : '';
  return caixa('Redirecionamentos', `<ol style="margin:0;padding-left:22px">${lista}</ol>${aviso}`);
}

const observacoes = [];
if (a.conteudoTruncado) observacoes.push(`A página tem ${a.tamanhoConteudo.toLocaleString('pt-BR')} caracteres; a IA analisou só o começo.`);
if (a.visitado && a.status >= 400) observacoes.push(`O site respondeu com erro ${a.status}. A análise vale para a página de erro, não para o conteúdo normal.`);
if (a.avisoDns) observacoes.push(a.avisoDns);
const dataHora = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
};
if (intel.cache?.usado) {
  observacoes.push(`Reputação vinda do cache: as fontes foram consultadas em ${dataHora(intel.cache.em)} (nenhuma cota gasta agora). Para consultar de novo, escolha "Sim" em "Reanalisar site" no formulário.`);
} else if (intel.cache?.reanalise) {
  const anterior = dataHora(intel.cache.guardadoEm);
  observacoes.push(`Reanálise pedida: as fontes de reputação foram consultadas de novo agora${anterior ? ` (o resultado guardado em ${anterior} foi substituído)` : ''}.`);
}

// Links do alvo saem DESARMADOS (hxxp, [.]): ninguém abre um site malicioso clicando no relatório.
const html = `<div style="font-family:Segoe UI,Arial,sans-serif;background:#f1f5f9;padding:16px;color:#0f172a">
<div style="max-width:900px;margin:0 auto">
  <div style="background:#0f172a;color:#fff;padding:20px;border-radius:8px 8px 0 0;text-align:center">
    <div style="font-size:24px;font-weight:bold">Análise de segurança de site</div>
    <div style="font-size:13px;color:#cbd5e1;margin-top:4px">Scanner de Segurança Web · reputação + postura · ${a.visitado ? 'página lida uma vez, sem ataques' : 'modo só reputação: o site não foi acessado'}</div>
  </div>
  <div style="background:${v.fundo};border:1px solid #e2e8f0;border-top:4px solid ${v.cor};padding:12px 18px;margin:0 0 16px;font-size:14px">
    <table style="border-collapse:collapse">
      ${linha('Site:', `<code>${escapar(desarmar(a.urlOriginal))}</code>`)}
      ${a.urlFinal !== a.urlOriginal ? linha('Página final:', `<code>${escapar(desarmar(a.urlFinal))}</code>`) : ''}
      ${rel?.encurtador ? linha('Link encurtado:', `sim (${escapar(rel.encurtador)})`) : ''}
      ${rel?.papel === 'destino' ? linha('Destino (VirusTotal):', `<code>${escapar(desarmar(rel.url))}</code> <span style="color:#64748b">(não acessado)</span>`) : ''}
      ${rel?.destinoDesconhecido ? linha('Destino:', '<span style="color:#b45309">desconhecido: o encurtador não foi aberto e o VirusTotal não conhece o destino</span>') : ''}
      ${linha('IP:', escapar((a.ips ?? []).join(', ') || 'nenhum'))}
      ${a.visitado ? linha('Resposta:', `${escapar(a.status)} ${escapar(a.statusMessage)}`) : ''}
      ${linha('Data:', escapar(a.dataHora))}
      ${a.contexto ? linha('Contexto:', escapar(a.contexto)) : ''}
    </table>
    ${observacoes.map((o) => `<p style="margin:8px 0 0;color:#b45309;font-size:13px">⚠ ${escapar(o)}</p>`).join('')}
  </div>

  ${caixa('Parecer do analista SOC', blocoParecer())}
  ${caixa('Reputação e inteligência de ameaças', blocoInteligencia())}
  ${caixa('Sinais de risco (regras automáticas)', blocoSinais())}
  ${blocoDominio()}
  ${caixa('IOCs e parecer para copiar', blocoIocs())}
  ${blocoPostura()}
  ${a.visitado ? caixa('Análise da IA: conteúdo da página (HTML e JavaScript)', analiseIA(a.iaConteudo)) : ''}
  ${cadeiaRedirecionamentos()}
  ${a.visitado ? caixa('Cabeçalhos recebidos', tabelaCabecalhos()) : ''}

  <div style="font-size:12px;color:#64748b;text-align:center;padding:8px 12px 4px;line-height:1.5">
    As fontes de reputação são só consultadas: nenhuma URL é enviada para análise pública.
    O parecer da IA passa por travas automáticas, mas pode conter erros: confirme as evidências antes de bloquear ou liberar.
    Não substitui análise em sandbox nem teste de intrusão autorizado.
  </div>
</div>
</div>`;

return [{
  json: {
    html,
    assunto: `RESULTADO [ANALISE DE SITE WEB] ${a.host} - Parecer: risco ${riscoFinal}/100`,
    veredito: p.veredito,
    nota: p.nota,
    risco: riscoFinal,
    gravidade: p.gravidade,
    host: a.host,
    textoChamado,
  },
}];
