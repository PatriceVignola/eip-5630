// This module implements the EIP-5630 for testing purposes because, at this
// time, popular wallets like MetaMask do not support it yet. This code is for
// testing purposes only and shouldn't be used in production.
// DO NOT CALL THESE FUNCTIONS WITH YOUR PERSONAL PRIVATE KEY.

import keccak256 from "keccak256";
import secp256k1 from "secp256k1";
import { decrypt } from "eciesjs";

// Implements the X9.63 key derivation function as described in
// https://www.secg.org/sec1-v2.pdf#subsubsection.3.6.1
function X963KDF(publicKey: Buffer, secretSigningKey: Buffer): Buffer {
  const counter = Buffer.allocUnsafe(4);
  counter.writeUInt32BE(1, 0);
  const keyData = Buffer.concat([secretSigningKey, counter, publicKey]);
  return keccak256(keyData);
}

// Implements the eth_getEncryptionPublicKey function as described in
// https://eips.ethereum.org/EIPS/eip-5630
export function eth_getEncryptionPublicKey(
  publicKey: string,
  privateKey: string
) {
  const publicKeyBuffer = Buffer.from(publicKey, "hex");
  const privateKeyBuffer = Buffer.from(privateKey, "hex");
  const secretDecryptionKey = X963KDF(publicKeyBuffer, privateKeyBuffer);
  const publicDecryptionKey = Buffer.from(
    secp256k1.publicKeyCreate(secretDecryptionKey)
  );
  return "0x" + publicDecryptionKey.toString("hex");
}

// Implements the eth_decrypt function as described in
// https://eips.ethereum.org/EIPS/eip-5630
export function eth_decrypt(
  publicKey: string,
  privateKey: string,
  encryptedMessage: Buffer
) {
  const publicKeyBuffer = Buffer.from(publicKey, "hex");
  const privateKeyBuffer = Buffer.from(privateKey, "hex");
  const secretDecryptionKey = X963KDF(publicKeyBuffer, privateKeyBuffer);
  const decryptedMessage = decrypt(secretDecryptionKey, encryptedMessage);
  return decryptedMessage.toString("utf-8");
}
