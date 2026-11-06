// Nó "Gerar relatório": monta o relatório em HTML (o mesmo para a tela e para o e-mail).
// Só usa estilos inline, que funcionam no Outlook e dentro da página do formulário.
const a = $input.first().json.auditoria;

const CORES_NOTA = { 'A+': '#15803d', A: '#15803d', 'A-': '#15803d', 'B+': '#1d4ed8', B: '#1d4ed8', 'B-': '#1d4ed8', 'C+': '#b45309', C: '#b45309', 'C-': '#b45309', D: '#b91c1c', F: '#b91c1c' };
const NIVEIS = {
  alto: { rotulo: 'Alto', cor: '#b91c1c', fundo: '#fef2f2' },
  medio: { rotulo: 'Médio', cor: '#b45309', fundo: '#fffbeb' },
  baixo: { rotulo: 'Baixo', cor: '#1d4ed8', fundo: '#eff6ff' },
  info: { rotulo: 'Info', cor: '#475569', fundo: '#f8fafc' },
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

const caixa = (titulo, conteudo) => `
  <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:16px 18px;margin:0 0 16px">
    <h2 style="font-size:18px;color:#0f172a;margin:0 0 12px">${titulo}</h2>
    ${conteudo}
  </div>`;

// Selos só dos 6 cabeçalhos que todo site deveria ter (COEP/CORP etc. dependem do caso).
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
        <div><span style="display:inline-block;font-size:11px;font-weight:bold;color:#fff;background:${n.cor};padding:2px 6px;border-radius:3px;margin-right:6px">${n.rotulo}</span><strong style="color:#0f172a">${escapar(x.titulo)}</strong></div>
        <div style="margin-top:6px;color:#334155">${escapar(x.detalhe)}</div>
        ${x.correcao ? `<div style="margin-top:6px"><span style="color:#475569;font-size:13px">Como corrigir:</span><pre style="background:#0f172a;color:#e2e8f0;padding:8px 10px;border-radius:6px;margin:4px 0 0;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all">${escapar(x.correcao)}</pre></div>` : ''}
      </div>`;
  }).join('');
}

function analiseIA(resultado) {
  if (!resultado.ok) return `<p style="margin:0;color:#b45309">${escapar(resultado.texto)}</p>`;
  return `<div style="color:#334155;font-size:14px;line-height:1.5">${markdownParaHtml(resultado.texto)}</div>`;
}

function tabelaCabecalhos() {
  const linhas = Object.entries(a.cabecalhos).flatMap(([nome, valor]) =>
    (Array.isArray(valor) ? valor : [valor]).map((v) => `
      <tr>
        <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-weight:bold;vertical-align:top;white-space:nowrap;color:${NOMES_CABECALHOS[nome] ? '#15803d' : '#0f172a'}">${escapar(nome)}</td>
        <td style="padding:6px 8px;border-bottom:1px solid #e2e8f0;font-family:Consolas,monospace;font-size:12px;word-break:break-all">${escapar(v)}</td>
      </tr>`));
  if (!linhas.length) return '<p style="margin:0">Nenhum cabeçalho recebido.</p>';
  return `<table style="width:100%;border-collapse:collapse;font-size:13px">${linhas.join('')}</table>`;
}

function cadeiaRedirecionamentos() {
  if (!a.cadeia || a.cadeia.length <= 1) return '';
  const itens = a.cadeia.map((c) => `<li style="margin:3px 0"><code>${escapar(c.status)}</code> ${linkSeguro(c.url)}</li>`).join('');
  const aviso = a.parouNoLimite ? '<p style="margin:8px 0 0;color:#b45309">O site ainda pedia outro redirecionamento; o scanner parou no limite de 5.</p>' : '';
  return caixa('Redirecionamentos', `<ol style="margin:0;padding-left:22px">${itens}</ol>${aviso}`);
}

const observacoes = [];
if (a.conteudoTruncado) observacoes.push(`A página tem ${a.tamanhoConteudo.toLocaleString('pt-BR')} caracteres; a IA analisou só o começo.`);
if (a.status >= 400) observacoes.push(`O site respondeu com erro ${a.status}. A análise vale para a página de erro, não para o conteúdo normal.`);

const html = `<div style="font-family:Segoe UI,Arial,sans-serif;background:#f1f5f9;padding:16px;color:#0f172a">
<div style="max-width:900px;margin:0 auto">
  <div style="background:#0f172a;color:#fff;padding:20px;border-radius:8px 8px 0 0;text-align:center">
    <div style="font-size:24px;font-weight:bold">Relatório de segurança do site</div>
    <div style="font-size:13px;color:#cbd5e1;margin-top:4px">Scanner de Segurança Web · análise passiva, sem ataques</div>
  </div>
  <div style="height:16px"></div>

  ${caixa('Resumo', `
    <table style="width:100%;border-collapse:collapse"><tr>
      <td style="width:110px;vertical-align:top;padding-right:14px">
        <div style="width:96px;height:96px;line-height:96px;text-align:center;font-size:44px;font-weight:bold;color:#fff;border-radius:8px;background:${CORES_NOTA[a.nota] ?? '#b91c1c'}">${escapar(a.nota)}</div>
      </td>
      <td style="vertical-align:top;font-size:14px">
        <table style="border-collapse:collapse">
          <tr><td style="padding:2px 10px 2px 0;color:#475569">Site:</td><td>${linkSeguro(a.urlOriginal)}</td></tr>
          ${a.urlFinal !== a.urlOriginal ? `<tr><td style="padding:2px 10px 2px 0;color:#475569">Página final:</td><td>${linkSeguro(a.urlFinal)}</td></tr>` : ''}
          <tr><td style="padding:2px 10px 2px 0;color:#475569">IP:</td><td>${escapar((a.ips ?? []).join(', '))}</td></tr>
          <tr><td style="padding:2px 10px 2px 0;color:#475569">Resposta:</td><td>${escapar(a.status)} ${escapar(a.statusMessage)}</td></tr>
          <tr><td style="padding:2px 10px 2px 0;color:#475569">Data:</td><td>${escapar(a.dataHora)}</td></tr>
          <tr><td style="padding:2px 10px 2px 0;color:#475569">Problemas:</td><td><strong style="color:#b91c1c">${a.totalAlto} alto</strong> · <strong style="color:#b45309">${a.totalMedio} médio</strong> · <strong style="color:#1d4ed8">${a.totalBaixo} baixo</strong></td></tr>
        </table>
      </td>
    </tr></table>
    <div style="margin-top:12px">${selos()}</div>
    ${observacoes.map((o) => `<p style="margin:8px 0 0;color:#b45309;font-size:13px">⚠ ${escapar(o)}</p>`).join('')}
  `)}

  ${caixa('Achados automáticos (cabeçalhos e cookies)', listaAchados())}
  ${caixa('Análise da IA: configuração (cabeçalhos e cookies)', analiseIA(a.iaConfiguracao))}
  ${caixa('Análise da IA: conteúdo da página (HTML e JavaScript)', analiseIA(a.iaConteudo))}
  ${cadeiaRedirecionamentos()}
  ${caixa('Cabeçalhos recebidos', tabelaCabecalhos())}

  <div style="font-size:12px;color:#64748b;text-align:center;padding:8px 12px 4px;line-height:1.5">
    Análise automática e passiva: o scanner fez uma única leitura da página, como um navegador, sem testar ataques.
    A nota vem só dos cabeçalhos reais; a análise da IA é complementar e pode conter erros, então confirme antes de corrigir.
    Para uma avaliação completa, faça um teste de intrusão autorizado.
  </div>
</div>
</div>`;

return [{
  json: {
    html,
    assunto: `Relatório de segurança: ${a.host} (nota ${a.nota})`,
    nota: a.nota,
    host: a.host,
  },
}];
