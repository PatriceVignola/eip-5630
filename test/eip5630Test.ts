import { expect } from "chai";
import { eth_getEncryptionPublicKey, eth_decrypt } from "../eip5630.js";
import { encrypt } from "eciesjs";

describe("eth_getEncryptionPublicKey", function () {
  it("returns the right secp256k1 decryption key", function () {
    const privateKey =
      "439047a312c8502d7dd276540e89fe6639d39da1d8466f79be390579d7eaa3b2";
    const encryptionKey = eth_getEncryptionPublicKey(privateKey);
    expect(encryptionKey).to.be.equal(
      "0x023e5feced05739d8aad239b037787ba763706fb603e3e92ff0a629e8b4ec2f9be"
    );
  });
});

describe("eth_decrypt", function () {
  it("correctly decrypts a message via the public and private keys", function () {
    const privateKey =
      "439047a312c8502d7dd276540e89fe6639d39da1d8466f79be390579d7eaa3b2";

    // Generate the encrytion key
    const encryptionKey = eth_getEncryptionPublicKey(privateKey);

    // Encrypt the message
    const encryptedMessage = encrypt(
      encryptionKey,
      Buffer.from("Hello Beautiful World!")
    );

    // Decrypt the message via eth_decrypt
    const decryptedMessage = eth_decrypt(privateKey, encryptedMessage);

    expect(decryptedMessage).to.be.equal("Hello Beautiful World!");
  });
});
