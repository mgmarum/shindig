package org.apache.shindig.gadgets.oauth2.persistence;

import java.io.Serializable;

import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2EncryptionException;

import com.google.inject.Inject;

public class OAuth2ClientPersistence implements OAuth2Client, Serializable {
  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  
  private final OAuth2Encrypter encrypter;

  private String providerName;
  private String redirectUri;
  private String gadgetUri;
  private String key;
  private String secret;
  private String encryptedSecret;
  private Flow flow = Flow.UNKNOWN;
  private Type type = Type.UNKNOWN;

  
  @Inject
  public OAuth2ClientPersistence(final OAuth2Encrypter encrypter) {
    this.encrypter = encrypter;
  }

  public OAuth2Encrypter getEncrypter() {
    return this.encrypter;
  }

  public String getProviderName() {
    return this.providerName;
  }

  public void setProviderName(final String providerName) {
    this.providerName = providerName;
  }

  public String getRedirectUri() {
    return this.redirectUri;
  }

  public void setRedirectUri(final String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public String getGadgetUri() {
    return this.gadgetUri;
  }

  public void setGadgetUri(final String gadgetUri) {
    this.gadgetUri = gadgetUri;
  }

  public String getKey() {
    return this.key;
  }

  public void setKey(final String key) {
    this.key = key;
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

  public OAuth2Client.Flow getFlow() {
    return this.flow;
  }

  public void setFlow(final OAuth2Client.Flow flow) {
    this.flow = flow;
  }

  public OAuth2Client.Type getType() {
    return this.type;
  }

  public void setType(final OAuth2Client.Type type) {
    this.type = type;
  }

  @Override
  public boolean equals(final Object obj) {
    boolean ret = false;
    if (OAuth2Client.class.isInstance(obj)) {
      final OAuth2Client otherClient = (OAuth2Client) obj;
      if (this.providerName.equals(otherClient.getProviderName())) {
        if (this.gadgetUri.equals(otherClient.getGadgetUri())) {
          ret = true;
        }
      }
    }

    return ret;
  }

  @Override
  public int hashCode() {
    if ((this.providerName != null) && (this.gadgetUri != null)) {
      return (this.providerName + ":" + this.gadgetUri).hashCode();
    }

    return 0;
  }

  @Override
  public String toString() {
    return "org.apache.shindig.gadgets.oauth2.persistence.sample.OAuth2ClientImpl: providerName = "
        + this.providerName + " , redirectUri = " + this.redirectUri + " , gadgetUri = "
        + this.gadgetUri + " , key = " + this.key + " , flow = " + this.flow.name() + " , type = "
        + this.type.name();
  }

}
