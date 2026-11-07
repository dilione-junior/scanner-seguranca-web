// Nó "Consolidar inteligência": junta o que as fontes de reputação disseram, aponta sinais de risco
// e calcula um veredito e uma nota AUTOMÁTICOS (0 a 100, quanto maior, mais seguro).
// Eles servem de base para a IA analista SOC e de reserva se a IA falhar.
//
// Cuidado com falso positivo: plataformas grandes (github.com, drive.google.com...) hospedam
// arquivos de terceiros e aparecem no URLhaus/ThreatFox por causa de UMA URL. Por isso só o
// casamento EXATO com a URL ou o host analisado pesa forte, e domínios populares pesam menos.
const a = $input.first().json.auditoria;
const agora = Date.now();

// Respostas guardadas no Redis numa análise recente da mesma URL (nó "Usar cache").
let cache = { hit: false, respostas: {}, em: '' };
try { cache = $('Usar cache').first().json; } catch (erro) { /* sem cache */ }

function resposta(nome) {
  let json;
  if (cache.hit && cache.respostas?.[nome]) {
    json = cache.respostas[nome];
  } else {
    try {
      json = $(nome).first().json;
    } catch (erro) {
      return { executada: false, ok: false, status: 0, corpo: null, erro: 'não consultada' };
    }
  }
  if (json.error && json.statusCode === undefined) {
    return { executada: true, ok: false, status: 0, corpo: null, erro: textoCurto(json.error.message ?? json.error, 120) };
  }
  let corpo = json.body ?? null;
  if (typeof corpo === 'string') {
    try { corpo = JSON.parse(corpo); } catch (erro) { /* resposta não é JSON */ }
  }
  const status = Number(json.statusCode ?? 0);
  return { executada: true, ok: status >= 200 && status < 300, status, corpo, erro: status >= 300 ? `HTTP ${status}` : '' };
}

function erroDeFonte(r) {
  if (r.status === 401 || r.status === 403) return 'chave inválida ou sem permissão';
  if (r.status === 429) return 'cota esgotada (limite de consultas)';
  return r.erro || 'sem resposta';
}

const fontes = {};
const sinais = [];
const sinal = (fonte, nivel, pontos, texto) => sinais.push({ fonte, nivel, pontos, texto: textoCurto(texto, 300) });
const consultadas = [];
const falharam = [];
const registra = (nome, deuCerto, motivo) => (deuCerto ? consultadas.push(nome) : falharam.push(`${nome}: ${motivo}`));

// Domínio popular (top 100 mil em algum ranking do VirusTotal ou na lista de confiáveis do OTX)?
// Calculado antes dos sinais, porque reduz o peso de listagens "do host" em plataformas grandes.
let popular = false;
{
  const ranks = Object.values(resposta('VirusTotal (domínio)').corpo?.data?.attributes?.popularity_ranks ?? {}).map((v) => Number(v?.rank)).filter((x) => x > 0);
  const otx = resposta('OTX').corpo?.validation ?? [];
  popular = ranks.some((x) => x <= 100000) || otx.some((v) => /whitelist/i.test(`${v.source} ${v.name}`));
}

// ---------------- VirusTotal: domínio (ou IP) ----------------
{
  const r = resposta('VirusTotal (domínio)');
  const at = r.corpo?.data?.attributes;
  if (r.ok && at) {
    const stats = at.last_analysis_stats ?? {};
    const ranks = Object.entries(at.popularity_ranks ?? {}).map(([fonte, v]) => ({ fonte, rank: Number(v?.rank) })).filter((x) => x.rank > 0);
    const melhorRank = ranks.length ? Math.min(...ranks.map((x) => x.rank)) : null;
    const cert = at.last_https_certificate;
    const validoAte = cert?.validity?.not_after ? Date.parse(cert.validity.not_after.replace(' ', 'T') + 'Z') : NaN;
    fontes.vtDominio = {
      malicioso: Number(stats.malicious ?? 0),
      suspeito: Number(stats.suspicious ?? 0),
      inofensivo: Number(stats.harmless ?? 0),
      naoDetectado: Number(stats.undetected ?? 0),
      reputacao: Number(at.reputation ?? 0),
      categorias: [...new Set(Object.values(at.categories ?? {}).map((c) => textoCurto(c, 60)))].slice(0, 6),
      motores: Object.entries(at.last_analysis_results ?? {}).filter(([, v]) => v?.category === 'malicious' || v?.category === 'suspicious').map(([motor, v]) => textoCurto(`${motor}: ${v.result}`, 60)).slice(0, 8),
      melhorRank,
      fonteRank: ranks.find((x) => x.rank === melhorRank)?.fonte ?? '',
      criadoEm: at.creation_date ? new Date(at.creation_date * 1000).toISOString().slice(0, 10) : '',
      registrador: textoCurto(at.registrar, 80),
      pais: textoCurto(at.country, 4),
      asn: at.asn ? `AS${at.asn} ${textoCurto(at.as_owner, 60)}` : '',
      certEmissor: textoCurto(cert?.issuer?.O ?? cert?.issuer?.CN, 80),
      certValidoAte: Number.isFinite(validoAte) ? new Date(validoAte).toISOString().slice(0, 10) : '',
      certDiasRestantes: Number.isFinite(validoAte) ? Math.floor((validoAte - agora) / 86400000) : null,
      link: `https://www.virustotal.com/gui/${a.ehIP ? 'ip-address' : 'domain'}/${encodeURIComponent(a.dominio)}`,
    };
    registra('VirusTotal (domínio)', true);
    const d = fontes.vtDominio;
    if (d.malicioso >= 5) sinal('VirusTotal', 'malicioso', 40, `${d.malicioso} motores marcam ${a.dominio} como malicioso.`);
    else if (d.malicioso >= 2) sinal('VirusTotal', popular ? 'info' : 'suspeito', popular ? 5 : 15, `${d.malicioso} motores marcam ${a.dominio} como malicioso${popular ? ' (domínio muito acessado: possível falso positivo)' : ''}.`);
    else if (d.malicioso === 1) sinal('VirusTotal', 'info', popular ? 0 : 5, `Só 1 motor marca ${a.dominio} como malicioso (${d.motores[0] ?? ''}). Detecção isolada costuma ser falso positivo.`);
    if (d.reputacao <= -10) sinal('VirusTotal', 'suspeito', 10, `Reputação da comunidade do VirusTotal negativa (${d.reputacao}).`);
    if (d.certDiasRestantes !== null && d.certDiasRestantes < 0) sinal('Certificado', 'suspeito', 10, `O último certificado HTTPS visto pelo VirusTotal expirou em ${d.certValidoAte}.`);
  } else if (r.executada) {
    registra('VirusTotal (domínio)', false, r.status === 404 ? 'domínio desconhecido' : erroDeFonte(r));
    if (r.status === 404) sinal('VirusTotal', 'suspeito', 10, `${a.dominio} nunca foi visto pelo VirusTotal: típico de domínio recém-criado.`);
  }
}

// ---------------- VirusTotal: URL exata ----------------
{
  const r = resposta('VirusTotal (URL)');
  const at = r.corpo?.data?.attributes;
  if (r.ok && at) {
    const stats = at.last_analysis_stats ?? {};
    fontes.vtUrl = {
      malicioso: Number(stats.malicious ?? 0),
      suspeito: Number(stats.suspicious ?? 0),
      inofensivo: Number(stats.harmless ?? 0),
      titulo: textoCurto(at.title, 120),
      ultimaAnalise: at.last_analysis_date ? new Date(at.last_analysis_date * 1000).toISOString().slice(0, 10) : '',
      motores: Object.entries(at.last_analysis_results ?? {}).filter(([, v]) => v?.category === 'malicious' || v?.category === 'suspicious').map(([motor, v]) => textoCurto(`${motor}: ${v.result}`, 60)).slice(0, 8),
      link: `https://www.virustotal.com/gui/url/${encodeURIComponent($('Preparar consultas').first().json.vtUrlId)}`,
    };
    registra('VirusTotal (URL)', true);
    const u = fontes.vtUrl;
    if (u.malicioso >= 3) sinal('VirusTotal', 'malicioso', 50, `${u.malicioso} motores marcam esta URL como maliciosa (${u.motores.slice(0, 3).join('; ')}).`);
    else if (u.malicioso >= 1 || u.suspeito >= 2) sinal('VirusTotal', popular ? 'info' : 'suspeito', popular ? 5 : 15, `${u.malicioso} detecção(ões) maliciosa(s) e ${u.suspeito} suspeita(s) para esta URL.`);
  } else if (r.executada) {
    if (r.status === 404) {
      fontes.vtUrl = { naoVista: true };
      registra('VirusTotal (URL)', true);
    } else registra('VirusTotal (URL)', false, erroDeFonte(r));
  }
}

// ---------------- URLhaus (abuse.ch): host distribuindo malware ----------------
{
  const r = resposta('URLhaus');
  const c = r.corpo;
  if (r.ok && c && (c.query_status === 'ok' || c.query_status === 'no_results')) {
    const urls = Array.isArray(c.urls) ? c.urls : [];
    const exata = urls.find((u) => [a.urlFinal, a.urlOriginal].map((x) => String(x).replace(/\/$/, '')).includes(String(u.url).replace(/\/$/, '')));
    const dbl = String(c.blacklists?.spamhaus_dbl ?? 'not listed');
    fontes.urlhaus = {
      listado: c.query_status === 'ok',
      totalUrls: Number(c.url_count ?? 0),
      online: urls.filter((u) => u.url_status === 'online').length,
      ameacas: [...new Set(urls.flatMap((u) => [u.threat, ...(u.tags ?? [])]).filter(Boolean).map((t) => textoCurto(t, 40)))].slice(0, 6),
      spamhausDbl: textoCurto(dbl, 40),
      exata: exata ? { status: textoCurto(exata.url_status, 20), ameaca: textoCurto(exata.threat, 40) } : null,
      link: c.urlhaus_reference ?? '',
    };
    registra('URLhaus', true);
    const u = fontes.urlhaus;
    if (u.exata) sinal('URLhaus', u.exata.status === 'online' ? 'malicioso' : 'suspeito', u.exata.status === 'online' ? 50 : 25, `Esta URL está no URLhaus (${u.exata.ameaca}, ${u.exata.status}).`);
    if (dbl !== 'not listed' && dbl !== '') sinal('Spamhaus DBL', popular ? 'suspeito' : 'malicioso', popular ? 10 : 35, `Domínio na lista Spamhaus DBL (${u.spamhausDbl}).`);
    if (!u.exata && u.listado) {
      if (popular) sinal('URLhaus', 'info', 0, `${u.totalUrls} URL(s) deste host já distribuíram malware. Plataformas grandes hospedam arquivos de terceiros: avalie a URL, não o domínio.`);
      else if (u.online > 0) sinal('URLhaus', 'malicioso', 35, `${u.online} URL(s) deste host distribuem malware agora (${u.ameacas.join(', ')}).`);
      else sinal('URLhaus', 'suspeito', 10, `Este host já distribuiu malware (${u.totalUrls} URL(s), hoje fora do ar).`);
    }
  } else if (r.executada) registra('URLhaus', false, erroDeFonte(r));
}

// ---------------- ThreatFox (abuse.ch): IOC de malware/C2 ----------------
{
  const r = resposta('ThreatFox');
  const c = r.corpo;
  if (r.ok && c && (c.query_status === 'ok' || c.query_status === 'no_result')) {
    const iocs = Array.isArray(c.data) ? c.data : [];
    const limpa = (x) => String(x ?? '').toLowerCase().replace(/\/$/, '');
    const alvos = [a.host, a.dominio, a.urlFinal, a.urlOriginal].map(limpa);
    const exatos = iocs.filter((i) => alvos.includes(limpa(i.ioc)) || alvos.includes(limpa(i.ioc).replace(/:\d+$/, '')));
    fontes.threatfox = {
      total: iocs.length,
      exatos: exatos.map((i) => ({ malware: textoCurto(i.malware_printable, 50), tipo: textoCurto(i.threat_type, 30), confianca: Number(i.confidence_level ?? 0) })).slice(0, 5),
    };
    registra('ThreatFox', true);
    const t = fontes.threatfox;
    if (t.exatos.length) sinal('ThreatFox', 'malicioso', 45, `IOC conhecido de ${t.exatos.map((x) => `${x.malware} (${x.tipo}, confiança ${x.confianca})`).join('; ')}.`);
    else if (t.total > 0) sinal('ThreatFox', popular ? 'info' : 'suspeito', popular ? 0 : 15, `${t.total} IOC(s) de malware em URLs deste host${popular ? ' (plataforma popular, conteúdo de terceiros)' : ''}.`);
  } else if (r.executada) registra('ThreatFox', false, erroDeFonte(r));
}

// ---------------- OTX (AlienVault) ----------------
{
  const r = resposta('OTX');
  const c = r.corpo;
  if (r.ok && c) {
    const validacao = (c.validation ?? []).map((v) => textoCurto(v.name ?? v.source, 40));
    const confiavel = (c.validation ?? []).some((v) => /whitelist/i.test(`${v.source} ${v.name}`));
    fontes.otx = { pulsos: Number(c.pulse_info?.count ?? 0), confiavel, validacao: validacao.slice(0, 4) };
    registra('OTX', true);
    if (fontes.otx.pulsos > 0 && !confiavel) sinal('OTX', 'suspeito', 10, `Aparece em ${fontes.otx.pulsos} relatório(s) de ameaça da comunidade OTX.`);
  } else if (r.executada) registra('OTX', false, erroDeFonte(r));
}

// ---------------- AbuseIPDB (IP do servidor) ----------------
if (a.ipPrincipal) {
  const r = resposta('AbuseIPDB');
  const d = r.corpo?.data;
  if (r.ok && d) {
    fontes.abuseipdb = {
      ip: a.ipPrincipal,
      pontuacao: Number(d.abuseConfidenceScore ?? 0),
      denuncias: Number(d.totalReports ?? 0),
      uso: textoCurto(d.usageType, 60),
      provedor: textoCurto(d.isp, 80),
      pais: textoCurto(d.countryCode, 4),
      tor: Boolean(d.isTor),
      confiavel: Boolean(d.isWhitelisted),
    };
    registra('AbuseIPDB', true);
    const b = fontes.abuseipdb;
    if (b.pontuacao >= 75) sinal('AbuseIPDB', 'suspeito', 15, `IP ${b.ip} com ${b.pontuacao}% de confiança de abuso (${b.denuncias} denúncias). Em hospedagem compartilhada o IP pode ser de outro site.`);
    else if (b.pontuacao >= 25) sinal('AbuseIPDB', 'info', 5, `IP ${b.ip} com ${b.pontuacao}% de confiança de abuso.`);
    if (b.tor) sinal('AbuseIPDB', 'suspeito', 10, `IP ${b.ip} é nó da rede Tor.`);
  } else if (r.executada) registra('AbuseIPDB', false, erroDeFonte(r));
}

// ---------------- Shodan InternetDB (portas e CVEs conhecidas do IP) ----------------
if (a.ipPrincipal) {
  const r = resposta('Shodan InternetDB');
  const PORTAS_RISCO = { 21: 'FTP', 23: 'Telnet', 445: 'SMB', 1433: 'SQL Server', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB' };
  if (r.ok && r.corpo) {
    const portas = (r.corpo.ports ?? []).map(Number).slice(0, 30);
    fontes.internetdb = {
      ip: a.ipPrincipal,
      portas,
      portasRisco: portas.filter((p) => PORTAS_RISCO[p]).map((p) => `${p} (${PORTAS_RISCO[p]})`),
      cves: (r.corpo.vulns ?? []).map((v) => textoCurto(v, 20)).slice(0, 15),
      totalCves: (r.corpo.vulns ?? []).length,
      tags: (r.corpo.tags ?? []).map((t) => textoCurto(t, 30)).slice(0, 6),
    };
    registra('Shodan InternetDB', true);
    const s = fontes.internetdb;
    if (s.portasRisco.length) sinal('Shodan', 'info', 8, `Serviços sensíveis expostos na internet no IP ${s.ip}: ${s.portasRisco.join(', ')}.`);
    if (s.totalCves) sinal('Shodan', 'info', 10, `O Shodan associa ${s.totalCves} CVE(s) ao IP ${s.ip} pela versão dos serviços (ex.: ${s.cves.slice(0, 3).join(', ')}). Confirme antes de concluir.`);
    if (s.tags.some((t) => /malware|c2|compromised/i.test(t))) sinal('Shodan', 'suspeito', 15, `Shodan marca o IP com: ${s.tags.join(', ')}.`);
  } else if (r.executada && r.status === 404) {
    fontes.internetdb = { ip: a.ipPrincipal, portas: [], portasRisco: [], cves: [], totalCves: 0, tags: [], semDados: true };
    registra('Shodan InternetDB', true);
  } else if (r.executada) registra('Shodan InternetDB', false, erroDeFonte(r));
}

// ---------------- RDAP: idade do domínio ----------------
if (!a.ehIP) {
  const r = resposta('RDAP (registro do domínio)');
  const eventos = r.corpo?.events ?? [];
  const data = (acao) => eventos.find((e) => e.eventAction === acao)?.eventDate ?? '';
  const registrador = (r.corpo?.entities ?? []).find((e) => (e.roles ?? []).includes('registrar'));
  const nomeRegistrador = (registrador?.vcardArray?.[1] ?? []).find((v) => v[0] === 'fn')?.[3] ?? '';
  let criado = data('registration') || fontes.vtDominio?.criadoEm || '';
  if (r.ok || criado) {
    const idadeDias = criado ? Math.floor((agora - Date.parse(criado)) / 86400000) : null;
    fontes.registro = {
      criadoEm: criado ? criado.slice(0, 10) : '',
      expiraEm: data('expiration').slice(0, 10),
      idadeDias: Number.isFinite(idadeDias) ? idadeDias : null,
      registrador: textoCurto(nomeRegistrador || fontes.vtDominio?.registrador, 80),
    };
    if (r.ok) registra('RDAP', true); else registra('RDAP', false, erroDeFonte(r) + ' (data veio do VirusTotal)');
    const idade = fontes.registro.idadeDias;
    if (idade !== null && idade < 30) sinal('Registro do domínio', 'suspeito', 25, `Domínio registrado há só ${idade} dia(s) (${fontes.registro.criadoEm}). Domínios novos são muito usados em phishing.`);
    else if (idade !== null && idade < 180) sinal('Registro do domínio', 'info', 10, `Domínio relativamente novo: ${idade} dias.`);
  } else if (r.executada) registra('RDAP', false, erroDeFonte(r));
}

// ---------------- DNS: proteção contra falsificação de e-mail (SPF/DMARC) e DNSSEC ----------------
if (!a.ehIP) {
  const txt = (nome) => {
    const r = resposta(nome);
    return { ok: r.ok, registros: (r.corpo?.Answer ?? []).filter((x) => x.type === 16).map((x) => String(x.data).replace(/^"|"$/g, '').replace(/"\s*"/g, '')) };
  };
  const spf = txt('DNS (SPF)');
  const dmarc = txt('DNS (DMARC)');
  const regSpf = spf.registros.find((x) => /^v=spf1/i.test(x)) ?? '';
  const regDmarc = dmarc.registros.find((x) => /^v=DMARC1/i.test(x)) ?? '';
  const politica = (regDmarc.match(/;\s*p=(\w+)/i) ?? [])[1]?.toLowerCase() ?? '';
  fontes.dnsEmail = { consultado: spf.ok || dmarc.ok, spf: textoCurto(regSpf, 200), dmarc: textoCurto(regDmarc, 200), politicaDmarc: politica, dnssec: Boolean(a.dnssec) };
  if (fontes.dnsEmail.consultado) {
    if (!regSpf) sinal('DNS', 'info', 3, `${a.dominio} não tem SPF: qualquer servidor pode mandar e-mail se passando pelo domínio.`);
    if (!regDmarc) sinal('DNS', 'info', 3, `${a.dominio} não tem DMARC: e-mails falsificados com o domínio não são rejeitados.`);
    else if (politica === 'none') sinal('DNS', 'info', 1, 'DMARC só monitora (p=none): e-mails falsificados ainda são entregues.');
  }
}

// ---------------- Mozilla Observatory (segunda opinião sobre a postura) ----------------
{
  const r = resposta('Mozilla Observatory');
  if (r.ok && r.corpo && !r.corpo.error) {
    fontes.observatory = {
      nota: textoCurto(r.corpo.grade, 4),
      pontos: Number(r.corpo.score ?? 0),
      testesFalhos: Number(r.corpo.tests_failed ?? 0),
      testesTotal: Number(r.corpo.tests_quantity ?? 0),
      link: `https://developer.mozilla.org/en-US/observatory/analyze?host=${encodeURIComponent(a.host)}`,
    };
    registra('Mozilla Observatory', true);
  } else if (r.executada) registra('Mozilla Observatory', false, r.corpo?.error ? textoCurto(r.corpo.error, 80) : erroDeFonte(r));
}

// ---------------- urlscan.io: histórico e análise num navegador real ----------------
{
  const busca = resposta('urlscan (busca)');
  const resultados = Array.isArray(busca.corpo?.results) ? busca.corpo.results : [];
  const envio = resposta('urlscan (enviar análise)');
  const nova = resposta('urlscan (resultado)');
  const anterior = resposta('urlscan (última análise)');

  if (busca.ok || envio.executada) {
    const historico = {
      total: Number(busca.corpo?.total ?? resultados.length),
      ultimas: resultados.slice(0, 5).map((r) => ({
        data: textoCurto(r.task?.time, 10),
        url: textoCurto(r.page?.url ?? r.task?.url, 160),
        tags: (r.task?.tags ?? []).map((t) => textoCurto(t, 30)).slice(0, 4),
      })),
      // Tags vêm de quem enviou a análise (inclusive robôs) e erram muito: só informam.
      tags: [...new Set(resultados.flatMap((r) => r.task?.tags ?? []).map((t) => textoCurto(t, 30)))].slice(0, 8),
    };

    // Lê um resultado completo (análise nova ou anterior) no mesmo formato.
    const ler = (r, propria) => {
      const c = r.corpo;
      if (!r.ok || !c?.task) return null;
      const geral = c.verdicts?.overall ?? {};
      const marcas = (geral.brands ?? []).map((b) => textoCurto(typeof b === 'string' ? b : b?.name ?? b?.key, 40)).filter(Boolean);
      return {
        propria,
        uuid: textoCurto(c.task.uuid, 40),
        data: textoCurto(c.task.time, 10),
        visibilidade: textoCurto(c.task.visibility, 12),
        url: textoCurto(c.page?.url, 200),
        titulo: textoCurto(c.page?.title, 120),
        dominioFinal: textoCurto(c.page?.domain, 100),
        ip: textoCurto(c.page?.ip, 45),
        pais: textoCurto(c.page?.country, 4),
        asn: textoCurto(`${c.page?.asn ?? ''} ${c.page?.asnname ?? ''}`, 80),
        emissorTls: textoCurto(c.page?.tlsIssuer, 80),
        idadeTlsDias: Number.isFinite(Number(c.page?.tlsAgeDays)) ? Number(c.page.tlsAgeDays) : null,
        malicioso: Boolean(geral.malicious),
        pontuacao: Number(geral.score ?? 0),
        marcas,
        categorias: (geral.categories ?? []).map((x) => textoCurto(x, 30)).slice(0, 5),
        dominiosContatados: (c.lists?.domains ?? []).map((d) => textoCurto(d, 80)).slice(0, 15),
        totalDominios: (c.lists?.domains ?? []).length,
        totalIps: (c.lists?.ips ?? []).length,
        paises: (c.lists?.countries ?? []).map((x) => textoCurto(x, 4)).slice(0, 8),
        link: `https://urlscan.io/result/${encodeURIComponent(c.task.uuid)}/`,
        print: `https://urlscan.io/screenshots/${encodeURIComponent(c.task.uuid)}.png`,
      };
    };

    let analise = ler(nova, true) ?? ler(anterior, false);
    let erroEnvio = '';
    if (envio.executada && !envio.corpo?.uuid) {
      erroEnvio = textoCurto(envio.corpo?.message ?? envio.corpo?.description ?? erroDeFonte(envio), 160);
    } else if (envio.executada && !ler(nova, true)) {
      erroEnvio = nova.status === 404 ? 'a análise não terminou a tempo (veja depois no link)' : erroDeFonte(nova);
      analise = ler(anterior, false);
    }
    fontes.urlscan = {
      historico,
      analise,
      erroEnvio,
      linkPendente: envio.corpo?.uuid && !analise?.propria ? `https://urlscan.io/result/${encodeURIComponent(envio.corpo.uuid)}/` : '',
    };
    registra('urlscan.io', Boolean(analise) || busca.ok, erroEnvio || erroDeFonte(busca));
    if (erroEnvio) falharam.push(`urlscan.io (análise nova): ${erroEnvio}`);

    if (analise) {
      const quando = analise.propria ? 'na análise feita agora' : `na análise de ${analise.data}`;
      const diasAtras = analise.data ? Math.floor((agora - Date.parse(analise.data)) / 86400000) : 999;
      const recente = analise.propria || diasAtras <= 30;
      if (analise.malicioso) {
        sinal('urlscan.io', recente ? 'malicioso' : 'suspeito', recente ? 45 : 15, `O urlscan.io classificou a página como maliciosa ${quando}${analise.categorias.length ? ` (${analise.categorias.join(', ')})` : ''}.`);
      }
      const dominioMarca = (m) => String(m).toLowerCase().replace(/[^a-z0-9]/g, '');
      const imitada = analise.marcas.filter((m) => dominioMarca(m) && !String(a.dominio).replace(/[^a-z0-9]/g, '').includes(dominioMarca(m)));
      if (imitada.length) sinal('urlscan.io', 'suspeito', 20, `A página parece imitar a marca ${imitada.join(', ')} ${quando}, mas o domínio é ${a.dominio}.`);
      if (analise.dominioFinal && analise.dominioFinal !== a.host && !analise.dominioFinal.endsWith(`.${a.dominio}`) && analise.dominioFinal !== a.dominio) {
        sinal('urlscan.io', 'info', 5, `No navegador do urlscan a página terminou em outro domínio: ${analise.dominioFinal} (redirecionamento por JavaScript?).`);
      }
    }
  } else if (busca.executada) registra('urlscan.io', false, erroDeFonte(busca));
}

// ---------------- Link encurtado / outra ponta da cadeia de redirecionamentos ----------------
{
  let rel = null;
  if (cache.hit) rel = cache.respostas?.['Link relacionado']?.body ?? null;
  else {
    try { rel = $('Link relacionado').first().json; } catch (erro) { /* não executado */ }
  }
  if (rel && (rel.consultar || rel.encurtador || rel.destinoDesconhecido)) {
    const rotulo = rel.papel === 'origem' ? 'link original' : 'destino';
    const lr = {
      papel: rel.papel === 'origem' ? 'origem' : rel.papel === 'destino' ? 'destino' : '',
      rotulo,
      url: textoCurto(rel.url, 300),
      host: textoCurto(rel.host, 100),
      encurtador: textoCurto(rel.encurtador, 60),
      destinoDesconhecido: Boolean(rel.destinoDesconhecido),
      vt: null,
      urlhaus: null,
    };
    if (rel.consultar) {
      const rv = resposta('VirusTotal (link relacionado)');
      const at = rv.corpo?.data?.attributes;
      if (rv.ok && at) {
        const st = at.last_analysis_stats ?? {};
        lr.vt = {
          malicioso: Number(st.malicious ?? 0),
          suspeito: Number(st.suspicious ?? 0),
          inofensivo: Number(st.harmless ?? 0),
          naoDetectado: Number(st.undetected ?? 0),
          ultimaAnalise: at.last_analysis_date ? new Date(at.last_analysis_date * 1000).toISOString().slice(0, 10) : '',
          motores: Object.entries(at.last_analysis_results ?? {}).filter(([, v]) => v?.category === 'malicious' || v?.category === 'suspicious').map(([motor, v]) => textoCurto(`${motor}: ${v.result}`, 60)).slice(0, 8),
          link: `https://www.virustotal.com/gui/url/${encodeURIComponent(rel.vtUrlId)}`,
        };
        registra(`VirusTotal (${rotulo})`, true);
        const v = lr.vt;
        if (v.malicioso >= 3) sinal('VirusTotal', 'malicioso', 50, `${v.malicioso} motores marcam o ${rotulo} ${desarmar(lr.url)} como malicioso (${v.motores.slice(0, 3).join('; ')}).`);
        else if (v.malicioso >= 1 || v.suspeito >= 2) sinal('VirusTotal', 'suspeito', 15, `${v.malicioso} detecção(ões) maliciosa(s) e ${v.suspeito} suspeita(s) para o ${rotulo} ${desarmar(lr.url)}.`);
      } else if (rv.executada) {
        if (rv.status === 404) {
          lr.vt = { naoVista: true };
          registra(`VirusTotal (${rotulo})`, true);
        } else registra(`VirusTotal (${rotulo})`, false, erroDeFonte(rv));
      }
      const ru = resposta('URLhaus (link relacionado)');
      const cu = ru.corpo;
      if (ru.ok && cu && (cu.query_status === 'ok' || cu.query_status === 'no_results')) {
        lr.urlhaus = cu.query_status === 'ok'
          ? { listada: true, status: textoCurto(cu.url_status, 20), ameaca: textoCurto(cu.threat, 40), link: String(cu.urlhaus_reference ?? '') }
          : { listada: false };
        registra(`URLhaus (${rotulo})`, true);
        const u = lr.urlhaus;
        if (u.listada) sinal('URLhaus', u.status === 'online' ? 'malicioso' : 'suspeito', u.status === 'online' ? 50 : 25, `O ${rotulo} ${desarmar(lr.url)} está no URLhaus (${u.ameaca}, ${u.status}).`);
      } else if (ru.executada) registra(`URLhaus (${rotulo})`, false, erroDeFonte(ru));
    }
    if (lr.destinoDesconhecido) {
      sinal('Encurtador', 'info', 10, `Link encurtado (${lr.encurtador || a.host}): o destino é desconhecido. O encurtador não foi aberto (modo só reputação) e o VirusTotal não conhece o destino. A reputação do encurtador não vale para o site de destino.`);
    } else if (lr.encurtador) {
      sinal('Encurtador', 'info', 0, lr.papel === 'destino'
        ? `Link encurtado (${lr.encurtador}): destino conhecido pelo VirusTotal é ${desarmar(lr.url)}, consultado também.`
        : `Link encurtado (${lr.encurtador}): o destino final foi analisado e o link original também foi consultado.`);
    }
    fontes.linkRelacionado = lr;
  }
}

// ---------------- Postura (só se o site foi visitado) ----------------
if (a.visitado) {
  const PESO_NOTA = { 'A+': 0, A: 0, 'A-': 0, 'B+': 3, B: 3, 'B-': 3, 'C+': 6, C: 6, 'C-': 6, D: 10, F: 12 };
  if (PESO_NOTA[a.nota]) sinal('Postura', 'info', PESO_NOTA[a.nota], `Cabeçalhos de segurança com nota ${a.nota} (${a.totalAlto} problema(s) alto(s), ${a.totalMedio} médio(s)).`);
  if (!a.ehHttps) sinal('Postura', 'suspeito', 10, 'A página é servida sem HTTPS: qualquer senha digitada trafega aberta.');
}
if (a.avisoDns) sinal('DNS', 'info', 0, a.avisoDns);

// ---------------- Veredito e nota automáticos ----------------
const REPUTACAO = ['VirusTotal (domínio)', 'VirusTotal (URL)', 'URLhaus', 'ThreatFox', 'OTX', 'AbuseIPDB', 'urlscan.io'];
const fontesReputacao = consultadas.filter((f) => REPUTACAO.includes(f)).length;
let veredito;
if (sinais.some((s) => s.nivel === 'malicioso')) veredito = 'malicioso';
else if (sinais.some((s) => s.nivel === 'suspeito')) veredito = 'suspeito';
else if (fontesReputacao >= 3) veredito = 'limpo';
else veredito = 'indeterminado';
// Link encurtado com destino desconhecido nunca é "limpo": só o encurtador foi avaliado.
if (veredito === 'limpo' && fontes.linkRelacionado?.destinoDesconhecido) veredito = 'indeterminado';

let nota = Math.max(0, 100 - sinais.reduce((soma, s) => soma + s.pontos, 0));
if (veredito === 'malicioso') nota = Math.min(nota, 20);
if (veredito === 'suspeito') nota = Math.min(nota, 60);

const ORDEM = { malicioso: 0, suspeito: 1, info: 2 };
sinais.sort((x, y) => ORDEM[x.nivel] - ORDEM[y.nivel] || y.pontos - x.pontos);

return [{
  json: {
    auditoria: {
      ...a,
      inteligencia: {
        fontes,
        sinais,
        popular,
        consultadas,
        falharam,
        fontesReputacao,
        vereditoAutomatico: veredito,
        notaAutomatica: nota,
        cache: { usado: Boolean(cache.hit), em: cache.hit ? cache.em : '' },
      },
    },
  },
}];
