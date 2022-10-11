// This module implements the EIP-5630 for testing purposes because, at this
// time, popular wallets like MetaMask do not support it yet. This code is for
// testing purposes only and shouldn't be used in production.
// DO NOT CALL THESE FUNCTIONS WITH YOUR PERSONAL PRIVATE KEY.

import keccak256 from "keccak256";
import secp256k1 from "secp256k1";
import { decrypt } from "eciesjs";

// Implements the X9.63 key derivation function as described in
// https://www.secg.org/sec1-v2.pdf#subsubsection.3.6.1
function X963KDF(address: Uint8Array, secretSigningKey: Uint8Array): Buffer {
  const counter = Buffer.allocUnsafe(4);
  counter.writeUInt32BE(1, 0);
  const keyData = Buffer.concat([secretSigningKey, counter, address]);
  return keccak256(keyData);
}

function publicKeyToAddress(publicKeyBuffer: Uint8Array): string {
  // Remove the first byte (0x04), which is the type byte for an Ethereum
  // address
  const address =
    "0x" +
    keccak256(Buffer.from(publicKeyBuffer.slice(1)))
      .subarray(-20)
      .toString("hex");
  return address;
}

function getSecretDecryptionKey(privateKey: string): Buffer {
  const privateKeyBuffer = Buffer.from(privateKey, "hex");
  const publicKeyBuffer = secp256k1.publicKeyCreate(privateKeyBuffer, false);
  const address = publicKeyToAddress(publicKeyBuffer);
  const addressBuffer = Buffer.from(address, "hex");
  const secretDecryptionKey = X963KDF(addressBuffer, privateKeyBuffer);
  return secretDecryptionKey;
}

// Implements the eth_getEncryptionPublicKey function as described in
// https://eips.ethereum.org/EIPS/eip-5630
export function eth_getEncryptionPublicKey(privateKey: string): string {
  const secretDecryptionKey = getSecretDecryptionKey(privateKey);
  const publicDecryptionKey = Buffer.from(
    secp256k1.publicKeyCreate(secretDecryptionKey)
  );
  return "0x" + publicDecryptionKey.toString("hex");
}

// Implements the eth_decrypt function as described in
// https://eips.ethereum.org/EIPS/eip-5630
export function eth_decrypt(
  privateKey: string,
  encryptedMessage: Buffer
): Buffer {
  const secretDecryptionKey = getSecretDecryptionKey(privateKey);
  const decryptedMessage = decrypt(secretDecryptionKey, encryptedMessage);
  return decryptedMessage;
}
