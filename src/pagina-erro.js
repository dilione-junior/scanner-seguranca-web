// Nó "Página de erro": mostra na tela por que o site não foi analisado
// (endereço recusado, domínio inexistente, certificado inválido, site fora do ar etc.).
const entrada = $input.first().json;
let motivo = entrada.motivo;

if (!motivo) {
  const tecnico = String(entrada.error?.message ?? entrada.error ?? entrada.message ?? 'erro desconhecido');
  const t = tecnico.toLowerCase();
  if (t.includes('certificate') || t.includes('self signed') || t.includes('ssl') || t.includes('tls')) {
    motivo = 'O certificado HTTPS do site é inválido, expirado ou não confiável. Isso já é um problema de segurança: o navegador também mostraria um alerta para os visitantes.';
  } else if (t.includes('enotfound') || t.includes('eai_again')) {
    motivo = 'O domínio não foi encontrado.';
  } else if (t.includes('timeout') || t.includes('timedout') || t.includes('etimedout')) {
    motivo = 'O site demorou demais para responder (mais de 20 segundos).';
  } else if (t.includes('econnrefused') || t.includes('econnreset') || t.includes('socket hang up')) {
    motivo = 'O site recusou ou encerrou a conexão.';
  } else {
    motivo = 'Não foi possível acessar o site.';
  }
  motivo += ` Detalhe técnico: ${tecnico.slice(0, 300)}`;
}

const html = `<div style="font-family:Segoe UI,Arial,sans-serif;background:#f1f5f9;padding:16px;color:#0f172a">
  <div style="max-width:640px;margin:40px auto;background:#fff;border:1px solid #e2e8f0;border-left:5px solid #b91c1c;border-radius:8px;padding:20px 22px">
    <div style="font-size:20px;font-weight:bold;margin-bottom:8px">Não foi possível analisar este site</div>
    <p style="margin:0 0 12px;color:#334155;line-height:1.5">${escapar(motivo)}</p>
    <p style="margin:0;color:#475569;font-size:13px">Endereço informado: <code>${escapar($('Configuração').first().json.url ?? '')}</code></p>
    <p style="margin:16px 0 0;color:#475569;font-size:13px">Recarregue a página (F5) para tentar outro endereço.</p>
  </div>
</div>`;

return [{ json: { html } }];
