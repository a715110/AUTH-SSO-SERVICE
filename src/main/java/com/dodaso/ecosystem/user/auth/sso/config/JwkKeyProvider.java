package com.dodaso.ecosystem.user.auth.sso.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Supplies the authorization server's signing key so it survives restarts. A key that changes
 * at every start invalidates every issued token and breaks any service that validates them.
 *
 * <p>Resolution order:
 * <ol>
 *   <li>{@code privateKeyPem}: a PKCS8 RSA private key in PEM form (Key Vault secret
 *       {@code authserver-jwk-private-key} in the cloud). Literal "\n" sequences are accepted
 *       for secret stores that flatten line breaks.
 *   <li>{@code keyFile}: a PEM file that is loaded when present, and generated then saved
 *       when absent (local development).
 *   <li>Neither: startup fails. A customer instance must never silently sign with a
 *       throwaway key.
 * </ol>
 * The key id is the RFC 7638 thumbprint of the public key, so it is stable too.
 */
final class JwkKeyProvider {

  private static final String BEGIN = "-----BEGIN PRIVATE KEY-----";
  private static final String END = "-----END PRIVATE KEY-----";

  private JwkKeyProvider() {}

  static RSAKey resolve(String privateKeyPem, String keyFile) {
    try {
      if (privateKeyPem != null && !privateKeyPem.isBlank()) {
        return toRsaKey(parsePem(privateKeyPem));
      }
      if (keyFile != null && !keyFile.isBlank()) {
        Path path = Path.of(keyFile);
        if (Files.exists(path)) {
          return toRsaKey(parsePem(Files.readString(path, StandardCharsets.UTF_8)));
        }
        KeyPair pair = generate();
        write(path, (RSAPrivateCrtKey) pair.getPrivate());
        return toRsaKey((RSAPrivateCrtKey) pair.getPrivate());
      }
    } catch (Exception e) {
      throw new IllegalStateException("Cannot load the authorization server signing key: " + e.getMessage(), e);
    }
    throw new IllegalStateException(
        "No signing key configured. Set dodaso.sso.jwk-private-key (Key Vault secret "
            + "authserver-jwk-private-key) or, for local development only, dodaso.sso.jwk-key-file.");
  }

  static RSAPrivateCrtKey parsePem(String pem) throws Exception {
    String body =
        pem.replace("\\n", "\n").replace(BEGIN, "").replace(END, "").replaceAll("\\s", "");
    byte[] der = Base64.getDecoder().decode(body);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    java.security.PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(der));
    if (!(key instanceof RSAPrivateCrtKey crt)) {
      throw new IllegalArgumentException("Key is not an RSA CRT private key");
    }
    return crt;
  }

  static String toPem(RSAPrivateCrtKey key) {
    String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
        .encodeToString(key.getEncoded());
    return BEGIN + "\n" + b64 + "\n" + END + "\n";
  }

  private static KeyPair generate() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(2048);
    return g.generateKeyPair();
  }

  private static void write(Path path, RSAPrivateCrtKey key) throws IOException {
    if (path.getParent() != null) {
      Files.createDirectories(path.getParent());
    }
    Files.writeString(path, toPem(key), StandardCharsets.UTF_8);
    try {
      Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    } catch (UnsupportedOperationException | IOException ignored) {
      // Non POSIX file system (Windows): the user profile folder permissions apply.
    }
  }

  private static RSAKey toRsaKey(RSAPrivateCrtKey priv) throws Exception {
    RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA")
        .generatePublic(new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
    RSAKey unsigned = new RSAKey.Builder(pub).privateKey(priv).build();
    try {
      return new RSAKey.Builder(pub).privateKey(priv).keyID(unsigned.computeThumbprint().toString()).build();
    } catch (JOSEException e) {
      throw new IllegalStateException(e);
    }
  }
}
