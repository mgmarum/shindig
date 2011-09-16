package org.apache.shindig.gadgets.oauth2.persistence.sample;

import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Encrypter;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2EncryptionException;

import com.google.inject.Inject;
import com.google.inject.Singleton;

@Singleton
public class NoOpEncrypter implements OAuth2Encrypter {
  @Inject
  public NoOpEncrypter() {

  }

  public String encrypt(final String plainSecret) throws OAuth2EncryptionException {
    return plainSecret;
  }

  public String decrypt(final String encryptedSecret) throws OAuth2EncryptionException {
    return encryptedSecret;
  }
}
