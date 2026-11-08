// Nó "Usar registro do URLhaus": troca o endereço informado (página do registro no URLhaus)
// pela URL maliciosa listada no registro e força o modo "só reputação": é malware conhecido,
// o scanner não deve baixar nem abrir. O contexto avisa o analista (e a IA) da troca.
// Se a API não responder, o endereço fica como estava e o nó "Validar URL" pede a URL certa.
const form = $('Registro de base de ameaças?').first().json;
const r = $input.first().json;
let corpo = r.body ?? null;
if (typeof corpo === 'string') {
  try { corpo = JSON.parse(corpo); } catch (erro) { corpo = null; }
}
const listada = String(corpo?.url ?? '').trim();
const status = Number(r.statusCode ?? 0);

if (status < 200 || status >= 300 || corpo?.query_status !== 'ok' || !/^https?:\/\//i.test(listada) || listada.length > 2048) {
  return [{ json: form }];
}

const tags = (Array.isArray(corpo.tags) ? corpo.tags : []).map((t) => textoCurto(t, 30)).filter(Boolean).slice(0, 5);
const detalhes = [textoCurto(corpo.threat, 40), textoCurto(corpo.url_status, 20), ...tags].filter(Boolean).join(', ');
const nota = `Endereço informado era a página do registro ${form.registroUrlhaus} do URLhaus (${detalhes}). `
  + 'Foi analisada a URL listada nesse registro, só por reputação (o scanner não a acessa).';
const contextoOriginal = String(form['Contexto (opcional)'] ?? '').trim();

return [{
  json: {
    ...form,
    'Endereço do site': listada,
    'Modo da análise': 'Só reputação (registro do URLhaus)',
    'Contexto (opcional)': contextoOriginal ? `${nota} ${contextoOriginal}` : nota,
    registroUrlhaus: form.registroUrlhaus,
  },
}];
