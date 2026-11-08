// Nó "Registro de base de ameaças?": se o endereço informado é a página de um registro do
// URLhaus (https://urlhaus.abuse.ch/url/<número>/), marca o número para o fluxo buscar, na API
// do URLhaus, a URL maliciosa listada nesse registro. Só lê o texto: nada é acessado aqui.
const form = $input.first().json;
const bruto = String(form['Endereço do site'] ?? '').trim();
let registro = null;
try {
  registro = paginaDeRegistro(analisarUrl(/^[a-z][a-z0-9+.-]*:\/\//i.test(bruto) ? bruto : 'https://' + bruto).href);
} catch (erro) { /* endereço inválido: o nó "Validar URL" explica o motivo */ }

return [{ json: { ...form, registroUrlhaus: registro?.idUrlhaus ?? '' } }];
