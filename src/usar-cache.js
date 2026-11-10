// Nó "Usar cache": lê o que o Redis devolveu para esta URL (respostas das fontes de reputação
// guardadas numa análise recente). Se não houver, se estiver estragado ou se o Redis falhou,
// segue como "sem cache" e as fontes são consultadas normalmente.
// Com "Reanalisar site = Sim" no formulário, o cache é ignorado mesmo válido: as fontes são
// consultadas de novo e o resultado novo substitui o guardado.
const VERSAO = 3;
const alvo = $('Preparar consultas').first().json;
const bruto = $input.first().json.cache;

let reanalise = false;
try { reanalise = $('Configuração').first().json.reanalisar === true; } catch (erro) { /* sem configuração: não reanalisa */ }

let guardado = null;
if (typeof bruto === 'string' && bruto.trim()) {
  try {
    const dados = JSON.parse(bruto);
    if (dados.versao === VERSAO && dados.urlFinal === alvo.urlFinal && dados.respostas && typeof dados.respostas === 'object') {
      guardado = dados;
    }
  } catch (erro) { /* cache estragado: ignora */ }
}

const hit = Boolean(guardado) && !reanalise;

return [{
  json: {
    hit,
    respostas: hit ? guardado.respostas : {},
    em: hit ? String(guardado.em ?? '') : '',
    chave: alvo.chaveCache,
    reanalise,
    // Data do resultado que a reanálise deixou de lado (vazio se não havia nada guardado).
    guardadoEm: reanalise && guardado ? String(guardado.em ?? '') : '',
  },
}];
