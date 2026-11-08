// Nó "Parecer final": lê a resposta da IA analista SOC (JSON) e aplica TRAVAS antes de aceitar.
//  - Evidência forte (veredito automático "malicioso") não pode ser desmentida pela IA.
//  - A nota da IA fica no máximo 30 pontos longe da nota automática e respeita o teto do veredito.
//  - Se a IA falhar ou responder algo fora do formato, valem o veredito e a nota automáticos.
// Assim, mesmo que um site consiga enganar a IA, o resultado não vira "seguro" sozinho.
const a = $('Consolidar inteligência').first().json.auditoria;
const { iaConteudo } = $('Montar dossiê').first().json;
const intel = a.inteligencia;
const resposta = $input.first().json;

const VEREDITOS = ['limpo', 'suspeito', 'malicioso', 'indeterminado'];
const TETO = { malicioso: 30, suspeito: 70, limpo: 100, indeterminado: 80 };
const lista = (x, max, tam = 300) => (Array.isArray(x) ? x : []).map((i) => textoCurto(typeof i === 'string' ? i : JSON.stringify(i), tam)).filter(Boolean).slice(0, max);

let ia = null;
let erroIA = '';
if (typeof resposta.output === 'string' && resposta.output.trim()) {
  const texto = resposta.output.trim();
  const inicio = texto.indexOf('{');
  const fim = texto.lastIndexOf('}');
  try {
    ia = JSON.parse(texto.slice(inicio, fim + 1));
  } catch (erro) {
    erroIA = 'a IA respondeu fora do formato combinado';
  }
} else {
  erroIA = textoCurto(resposta.error?.message ?? resposta.error ?? 'resposta vazia', 160);
}

const avisos = [];
let veredito = intel.vereditoAutomatico;
let nota = intel.notaAutomatica;
let origem = 'automatica';

if (ia && typeof ia === 'object') {
  const vIA = String(ia.veredito ?? '').toLowerCase().trim();
  const nIA = Math.round(Number(ia.nota));
  if (VEREDITOS.includes(vIA) && Number.isFinite(nIA)) {
    origem = 'ia';
    veredito = vIA;
    nota = Math.max(0, Math.min(100, nIA));
    if (intel.vereditoAutomatico === 'malicioso' && veredito !== 'malicioso') {
      avisos.push(`A IA classificou como "${veredito}", mas há evidência forte de ameaça nas fontes. Mantido "malicioso": revise as evidências antes de liberar.`);
      veredito = 'malicioso';
    } else if (intel.vereditoAutomatico === 'suspeito' && veredito === 'limpo') {
      avisos.push('A IA descartou os sinais automáticos de suspeita (veja a justificativa). Confirme antes de liberar.');
    }
    const minimo = Math.max(0, intel.notaAutomatica - 30);
    const maximo = Math.min(TETO[veredito], intel.notaAutomatica + 30);
    const ajustada = Math.max(minimo, Math.min(maximo, nota));
    if (ajustada !== nota) {
      avisos.push(`A nota da IA (${nota}) foi ajustada para ${ajustada}: ela fica no máximo 30 pontos longe da nota automática (${intel.notaAutomatica}) e até ${TETO[veredito]} para "${veredito}".`);
      nota = ajustada;
    }
  } else {
    erroIA = 'a IA não informou veredito e nota válidos';
  }
}
if (veredito === 'limpo' && intel.fontes?.linkRelacionado?.destinoDesconhecido) {
  avisos.push('Link encurtado com destino desconhecido: só o encurtador foi avaliado. Mantido "indeterminado".');
  veredito = 'indeterminado';
  nota = Math.min(nota, TETO.indeterminado);
}
if (origem === 'automatica') nota = Math.min(nota, TETO[veredito]);

const CONFIANCA = ['alta', 'media', 'baixa'];
const parecer = {
  origem,
  veredito,
  nota,
  confianca: origem === 'ia' && CONFIANCA.includes(String(ia.confianca).toLowerCase()) ? String(ia.confianca).toLowerCase()
    : intel.fontesReputacao >= 4 ? 'media' : 'baixa',
  classificacao: origem === 'ia' ? textoCurto(ia.classificacao, 80) : '',
  resumo: origem === 'ia' ? textoCurto(ia.resumo, 1200)
    : `Parecer automático (IA indisponível: ${erroIA}). Baseado em ${intel.fontesReputacao} fonte(s) de reputação e ${intel.sinais.length} sinal(is).`,
  evidencias: origem === 'ia' ? lista(ia.evidencias, 12) : intel.sinais.filter((s) => s.nivel !== 'info').map((s) => `${s.fonte}: ${s.texto}`).slice(0, 8),
  falsosPositivos: origem === 'ia' ? textoCurto(ia.falsos_positivos, 600) : '',
  acoes: origem === 'ia' && lista(ia.acoes, 10).length ? lista(ia.acoes, 10) : ({
    malicioso: [
      `Bloquear ${a.dominio} e ${a.ipPrincipal || 'os IPs'} no proxy/DNS/firewall.`,
      'Procurar nos logs de proxy, DNS e e-mail quem acessou ou recebeu o endereço.',
      'Se alguém digitou senha no site: trocar a senha, revogar sessões e conferir MFA.',
      'Abrir chamado e anexar os IOCs deste relatório.',
    ],
    suspeito: [
      'Não liberar o acesso até uma análise manual (sandbox, urlscan.io, VirusTotal).',
      'Procurar nos logs quem acessou o endereço e monitorar novos acessos.',
    ],
    indeterminado: ['Repetir a consulta mais tarde (fontes falharam) ou analisar manualmente.'],
    limpo: ['Nenhuma ação de contenção. Encaminhar as correções de postura ao responsável pelo site, se houver.'],
  })[veredito],
  correcoes: origem === 'ia' ? lista(ia.correcoes, 10) : [],
  mitre: origem === 'ia' ? lista(ia.mitre, 6, 80) : [],
  avisos,
  erroIA,
};

const GRAVIDADE = { malicioso: 'alta', suspeito: 'media', indeterminado: 'media', limpo: 'baixa' };
parecer.gravidade = GRAVIDADE[veredito];

return [{ json: { auditoria: { ...a, parecer, iaConteudo } } }];
