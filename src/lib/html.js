// ---- Biblioteca: HTML seguro ----
// Tudo o que vem do site analisado (cabeçalhos, HTML) ou da IA é texto NÃO confiável.
// Por isso tudo passa por escapar() antes de entrar no relatório: um site malicioso não consegue
// injetar HTML, scripts ou links no relatório mostrado na tela e enviado por e-mail.

function escapar(texto) {
  return String(texto ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Só deixa virar link um endereço http(s); qualquer outra coisa (javascript:, data:) vira texto.
function linkSeguro(url) {
  const texto = String(url ?? '');
  if (!/^https?:\/\//i.test(texto)) return escapar(texto);
  return `<a href="${escapar(texto)}" style="color:#1d4ed8;word-break:break-all">${escapar(texto)}</a>`;
}

// Formatação simples dentro de uma linha JÁ ESCAPADA: **negrito**, `código`.
function formatarLinha(textoEscapado) {
  return textoEscapado
    .replace(/`([^`]+)`/g, '<code style="background:#eef2f7;padding:1px 4px;border-radius:3px;font-family:Consolas,monospace;font-size:13px">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}

// Converte o Markdown da IA em HTML. Primeiro escapa, depois aplica a formatação,
// então nenhuma marcação vinda da IA ou do site chega crua ao relatório.
function markdownParaHtml(markdown) {
  const linhas = String(markdown ?? '').replace(/\r\n?/g, '\n').split('\n');
  const saida = [];
  let lista = null;
  let codigo = null;

  const fecharLista = () => {
    if (lista) { saida.push(`</${lista}>`); lista = null; }
  };

  for (const linha of linhas) {
    if (codigo !== null) {
      if (/^\s*```/.test(linha)) {
        saida.push(`<pre style="background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow-x:auto;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap">${escapar(codigo.join('\n'))}</pre>`);
        codigo = null;
      } else {
        codigo.push(linha);
      }
      continue;
    }
    if (/^\s*```/.test(linha)) { fecharLista(); codigo = []; continue; }

    const titulo = linha.match(/^\s*(#{1,6})\s+(.*)$/);
    if (titulo) {
      fecharLista();
      const nivel = titulo[1].length <= 2 ? 'h3' : 'h4';
      saida.push(`<${nivel} style="color:#0f172a;margin:16px 0 6px">${formatarLinha(escapar(titulo[2].replace(/\*\*/g, '')))}</${nivel}>`);
      continue;
    }

    const item = linha.match(/^\s*(?:([-*+])|(\d+)[.)])\s+(.*)$/);
    if (item) {
      const tipo = item[1] ? 'ul' : 'ol';
      if (lista !== tipo) { fecharLista(); saida.push(`<${tipo} style="margin:4px 0 8px;padding-left:22px">`); lista = tipo; }
      saida.push(`<li style="margin:3px 0">${formatarLinha(escapar(item[3]))}</li>`);
      continue;
    }

    if (!linha.trim()) { fecharLista(); continue; }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(linha)) { fecharLista(); continue; }
    fecharLista();
    saida.push(`<p style="margin:6px 0">${formatarLinha(escapar(linha.trim()))}</p>`);
  }
  if (codigo !== null) saida.push(`<pre style="background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;white-space:pre-wrap">${escapar(codigo.join('\n'))}</pre>`);
  fecharLista();
  return saida.join('\n');
}
// ---- fim da biblioteca ----
