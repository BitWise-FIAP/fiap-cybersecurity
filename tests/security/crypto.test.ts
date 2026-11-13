import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decryptPii,
  encryptPii,
  hashPii,
  maskSecret,
  safeEqual,
} from '../../backend/security/crypto';

const SECRET = 'chave-de-teste';

test('criptografa e descriptografa PII com AES-256-GCM', () => {
  const plain = 'Avenida Paulista, 1000 - (11) 98765-4321';
  const encrypted = encryptPii(plain, SECRET);
  assert.equal(encrypted.includes(plain), false);
  assert.equal(encrypted.startsWith('v1:'), true);
  assert.equal(decryptPii(encrypted, SECRET), plain);
});

test('não descriptografa com chave errada', () => {
  const encrypted = encryptPii('dado sensível', SECRET);
  assert.throws(() => decryptPii(encrypted, 'outra-chave'));
});

test('gera hash estável e máscara segura', () => {
  assert.equal(hashPii('529.982.247-25'), hashPii('529.982.247-25'));
  assert.notEqual(hashPii('529.982.247-25'), hashPii('529.982.247-24'));
  assert.equal(maskSecret('segredo'), 'se****do');
  assert.equal(maskSecret('abc'), '****');
});

test('compara tokens em tempo constante', () => {
  assert.equal(safeEqual('trajetoria-demo', 'trajetoria-demo'), true);
  assert.equal(safeEqual('trajetoria-demo', 'outro-token'), false);
  assert.equal(safeEqual('curto', 'token-mais-longo'), false);
});
