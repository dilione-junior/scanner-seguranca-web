// Nó "Usar cache": lê o que o Redis devolveu para esta URL (respostas das fontes de reputação
// guardadas numa análise recente). Se não houver, se estiver estragado ou se o Redis falhou,
// segue como "sem cache" e as fontes são consultadas normalmente.
const VERSAO = 2;
const alvo = $('Preparar consultas').first().json;
const bruto = $input.first().json.cache;

let hit = false;
let respostas = {};
let em = '';
if (typeof bruto === 'string' && bruto.trim()) {
  try {
    const dados = JSON.parse(bruto);
    if (dados.versao === VERSAO && dados.urlFinal === alvo.urlFinal && dados.respostas && typeof dados.respostas === 'object') {
      hit = true;
      respostas = dados.respostas;
      em = String(dados.em ?? '');
    }
  } catch (erro) { /* cache estragado: ignora */ }
}

return [{ json: { hit, respostas, em, chave: alvo.chaveCache } }];
