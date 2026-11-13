import test from 'node:test';
import assert from 'node:assert/strict';
import {
  containsSensitiveCategory,
  isValidCpf,
  maskPiiInString,
  safeErrorMessage,
  sanitizeFreeText,
  scanPii,
} from '../../src/security';

const VALID_CPF = '529.982.247-25';
const RAW_NAME = 'Ana Beatriz Souza';
const RAW_EMAIL = 'ana.souza@example.com';
const RAW_PHONE = '(11) 98765-4321';
const RAW_PASSWORD = 'senha-super-secreta';
const RAW_MEDICAL = 'Estou em tratamento para ansiedade e tomo medicamento controlado.';

test('valida CPF pelo dígito verificador', () => {
  assert.equal(isValidCpf(VALID_CPF), true);
  assert.equal(isValidCpf('111.111.111-11'), false);
  assert.equal(isValidCpf('529.982.247-24'), false);
});

test('detecta e mascara CPF, e-mail, telefone e CEP', () => {
  const result = scanPii({
    cpf: VALID_CPF,
    email: RAW_EMAIL,
    telefone: RAW_PHONE,
    cep: '01310-100',
  });

  const ruleIds = result.findings.map((finding) => finding.ruleId);
  assert.ok(ruleIds.includes('FIELD-cpf'));
  assert.ok(ruleIds.includes('PII-CPF'));
  assert.ok(ruleIds.includes('FIELD-email'));
  assert.ok(ruleIds.includes('PII-EMAIL'));
  assert.ok(ruleIds.includes('FIELD-telefone'));
  assert.ok(ruleIds.includes('PII-PHONE'));
  assert.ok(ruleIds.includes('FIELD-cep'));
  assert.ok(ruleIds.includes('PII-CEP'));

  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes(VALID_CPF), false);
  assert.equal(serialized.includes(RAW_EMAIL), false);
  assert.equal(serialized.includes(RAW_PHONE), false);

  const redacted = result.redacted as Record<string, unknown>;
  assert.equal(redacted.cpf, '[DOCUMENTO REMOVIDO]');
  assert.equal(redacted.email, '[CONTATO REMOVIDO]');
  assert.equal(redacted.telefone, '[CONTATO REMOVIDO]');
  assert.equal(redacted.cep, '[ENDEREÇO REMOVIDO]');
});

test('mapeia campos sensíveis mesmo sem padrão reconhecível', () => {
  const result = scanPii({
    nome: RAW_NAME,
    menor_de_idade: 1,
    senha: RAW_PASSWORD,
    comentario: 'Adorei a jaqueta!',
  });

  const categories = new Set(result.findings.map((finding) => finding.category));
  assert.ok(categories.has('identificacao'));
  assert.ok(categories.has('menor'));
  assert.ok(categories.has('credencial'));
  assert.equal(containsSensitiveCategory(result.findings), true);

  const redacted = result.redacted as Record<string, unknown>;
  assert.equal(redacted.nome, '[NOME REMOVIDO]');
  assert.equal(redacted.menor_de_idade, '***');
  assert.equal(redacted.senha, '********');
  assert.equal(redacted.comentario, 'Adorei a jaqueta!');
});

test('remove dado de saúde de texto livre', () => {
  const result = scanPii({ comentario: RAW_MEDICAL });
  const medical = result.findings.find((finding) => finding.ruleId === 'PII-HEALTH');
  assert.ok(medical);
  assert.equal(medical?.category, 'saude');
  assert.equal(medical?.severity, 'high');
  assert.equal(result.redacted && (result.redacted as Record<string, unknown>).comentario, '[DADO DE SAÚDE REMOVIDO]');
});

test('mascara PII em texto preservando o restante', () => {
  const text = `Meu CPF é ${VALID_CPF} e meu telefone é ${RAW_PHONE}.`;
  const masked = maskPiiInString(text);
  assert.equal(masked.includes(VALID_CPF), false);
  assert.equal(masked.includes(RAW_PHONE), false);
  assert.equal(masked.includes('Meu CPF é'), true);
  assert.equal(masked.includes('***.***.***-**'), true);
});

test('sanitiza texto livre e limita tamanho', () => {
  const sanitized = sanitizeFreeText(`Oi\n\nMeu CPF é ${VALID_CPF}`, 200);
  assert.equal(sanitized.includes(VALID_CPF), false);
  assert.equal(sanitized.includes('***.***.***-**'), true);
  assert.equal(sanitized.includes('\n'), false);
});

test('não vaza erro bruto em mensagens para o usuário', () => {
  assert.equal(
    safeErrorMessage(new Error('consentimento ausente')),
    'É necessário aceitar o termo de consentimento antes de continuar.',
  );
  assert.equal(
    safeErrorMessage(new Error('SQLITE_ERROR: no such table usuarios')),
    'Não foi possível concluir a operação. Tente novamente.',
  );
  assert.equal(
    safeErrorMessage(new Error('peça indisponível: Jaqueta')),
    'Uma das peças não está mais disponível. Volte ao pedido e revise a seleção.',
  );
});
