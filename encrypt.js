import forge from "node-forge";

export async function encryptSecret(pem, value) {
  let publicKey;

  try {
    if (pem.includes("BEGIN CERTIFICATE")) {
      const cert = forge.pki.certificateFromPem(pem);
      publicKey = cert.publicKey;
    } else {
      publicKey = forge.pki.publicKeyFromPem(pem);
    }
  } catch (error) {
    console.error("Invalid PEM file:", error);
    throw new Error("Unsupported PEM format. Please upload a valid public key or certificate.");
  }

  const encrypted = publicKey.encrypt(value, "RSA-OAEP", {
    md: forge.md.sha256.create(),
  });
  return forge.util.encode64(encrypted);
}
