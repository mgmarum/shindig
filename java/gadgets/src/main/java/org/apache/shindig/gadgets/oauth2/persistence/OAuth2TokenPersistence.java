package org.apache.shindig.gadgets.oauth2.persistence;

import java.io.Serializable;

import org.apache.shindig.gadgets.oauth2.OAuth2EncryptionException;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;

import com.google.inject.Inject;

public class OAuth2TokenPersistence implements OAuth2Token, Serializable {
  private static final long serialVersionUID = 1L;

  private final OAuth2Encrypter encrypter;

  private Type type;
  private String secret;
  private String encryptedSecret;
  private String providerName;
  private String gadgetUri;
  private String user;
  private String scope;
  private int expiresIn;
  private String tokenType;

  @Inject
  public OAuth2TokenPersistence(final OAuth2Encrypter encrypter) {
    this.encrypter = encrypter;
  }

  public Type getType() {
    return this.type;
  }

  public void setType(final Type type) {
    this.type = type;
  }

  public String getSecret() {
    return this.secret;
  }

  public void setSecret(final String secret) throws OAuth2EncryptionException {
    this.secret = secret;
    this.encryptedSecret = this.encrypter.encrypt(secret);
  }

  public String getEncryptedSecret() {
    return this.encryptedSecret;
  }

  public void setEncryptedSecret(final String encryptedSecret) throws OAuth2EncryptionException {
    this.encryptedSecret = encryptedSecret;
    this.secret = this.encrypter.decrypt(encryptedSecret);
  }

  public String getProviderName() {
    return this.providerName;
  }

  public void setProviderName(final String providerName) {
    this.providerName = providerName;
  }

  public String getGadgetUri() {
    return this.gadgetUri;
  }

  public void setGadgetUri(final String gadgetUri) {
    this.gadgetUri = gadgetUri;
  }

  public String getUser() {
    return this.user;
  }

  public void setUser(final String user) {
    this.user = user;
  }

  public String getScope() {
    return this.scope;
  }

  public void setScope(final String scope) {
    this.scope = scope;
  }

  public int getExpiresIn() {
    return this.expiresIn;
  }

  public void setExpiresIn(final int expiresIn) {
    this.expiresIn = expiresIn;
  }

  public String getTokenType() {
    return this.tokenType;
  }

  public void setTokenType(final String tokenType) {
    this.tokenType = tokenType;
  }

  @Override
  public boolean equals(final Object obj) {
    boolean ret = false;
    if (OAuth2TokenPersistence.class.isInstance(obj)) {
      final OAuth2TokenPersistence otherClient = (OAuth2TokenPersistence) obj;
      if (this.providerName.equals(otherClient.getProviderName())) {
        if (this.user.equals(otherClient.getUser())) {
          if (this.scope.equals(otherClient.getScope())) {
            if (this.type.equals(otherClient.getType())) {
              if (this.gadgetUri.equals(otherClient.getGadgetUri())) {
                ret = true;
              }
            }
          }
        }
      }
    }

    return ret;
  }

  @Override
  public int hashCode() {
    if ((this.providerName != null) && (this.gadgetUri != null)) {
      return (this.providerName + ":" + this.gadgetUri + ":" + this.user + ":" + this.scope + ":" + this.type)
          .hashCode();
    }

    return 0;
  }

  @Override
  public String toString() {
    return "org.apache.shindig.gadgets.oauth2.persistence.sample.OAuth2TokenImpl: providerName = "
        + this.providerName + " , user = " + this.user + " , gadgetUri = " + this.gadgetUri
        + " , scope = " + this.scope + " , tokenType = " + this.getTokenType() + " , expiresIn = "
        + this.expiresIn + " , type = " + this.type.name();
  }
}
