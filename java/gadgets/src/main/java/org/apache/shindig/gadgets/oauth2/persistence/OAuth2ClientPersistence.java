package org.apache.shindig.gadgets.oauth2.persistence;

import java.io.Serializable;

import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2EncryptionException;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;

import com.google.inject.Inject;

public class OAuth2ClientPersistence implements OAuth2Client, Serializable {
  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  private boolean allowModuleOverride;
  private String authorizationUrl;
  private String clientAuthenticationType;
  private String clientId;
  private String clientSecret;
  private String encryptedSecret;
  private final OAuth2Encrypter encrypter;
  private String gadgetUri;
  private String grantType = OAuth2Message.NO_GRANT_TYPE;
  private String redirectUri;
  private String serviceName;
  private String tokenUrl;
  private Type type = Type.UNKNOWN;

  @Inject
  public OAuth2ClientPersistence(final OAuth2Encrypter encrypter) {
    this.encrypter = encrypter;
  }

  @Override
  public boolean equals(final Object obj) {
    boolean ret = false;
    if (OAuth2Client.class.isInstance(obj)) {
      final OAuth2Client otherClient = (OAuth2Client) obj;
      if (this.serviceName.equals(otherClient.getServiceName())) {
        if (this.gadgetUri.equals(otherClient.getGadgetUri())) {
          ret = true;
        }
      }
    }

    return ret;
  }

  public String getAuthorizationUrl() {
    return this.authorizationUrl;
  }

  public String getClientAuthenticationType() {
    return this.clientAuthenticationType;
  }

  public String getClientId() {
    return this.clientId;
  }

  public String getClientSecret() {
    return this.clientSecret;
  }

  public String getEncryptedSecret() {
    return this.encryptedSecret;
  }

  public OAuth2Encrypter getEncrypter() {
    return this.encrypter;
  }

  public String getGadgetUri() {
    return this.gadgetUri;
  }

  public String getGrantType() {
    return this.grantType;
  }

  public String getRedirectUri() {
    return this.redirectUri;
  }

  public String getServiceName() {
    return this.serviceName;
  }

  public String getTokenUrl() {
    return this.tokenUrl;
  }

  public OAuth2Client.Type getType() {
    return this.type;
  }

  @Override
  public int hashCode() {
    if ((this.serviceName != null) && (this.gadgetUri != null)) {
      return (this.serviceName + ":" + this.gadgetUri).hashCode();
    }

    return 0;
  }

  public boolean isAllowModuleOverride() {
    return this.allowModuleOverride;
  }

  public void setAllowModuleOverride(final boolean alllowModuleOverride) {
    this.allowModuleOverride = alllowModuleOverride;
  }

  public void setAuthorizationUrl(final String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }

  public void setClientAuthenticationType(final String clientAuthenticationType) {
    this.clientAuthenticationType = clientAuthenticationType;
  }

  public void setClientId(final String clientId) {
    this.clientId = clientId;
  }

  public void setClientSecret(final String secret) throws OAuth2EncryptionException {
    this.clientSecret = secret;
    this.encryptedSecret = this.encrypter.encrypt(secret);
  }

  public void setEncryptedSecret(final String encryptedSecret) throws OAuth2EncryptionException {
    this.encryptedSecret = encryptedSecret;
    this.clientSecret = this.encrypter.decrypt(encryptedSecret);
  }

  public void setGadgetUri(final String gadgetUri) {
    this.gadgetUri = gadgetUri;
  }

  public void setGrantType(final String grantType) {
    this.grantType = grantType;
  }

  public void setRedirectUri(final String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public void setServiceName(final String serviceName) {
    this.serviceName = serviceName;
  }

  public void setTokenUrl(final String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }

  public void setType(final OAuth2Client.Type type) {
    this.type = type;
  }

  @Override
  public String toString() {
    return "org.apache.shindig.gadgets.oauth2.persistence.sample.OAuth2ClientImpl: serviceName = "
        + this.serviceName + " , redirectUri = " + this.redirectUri + " , gadgetUri = "
        + this.gadgetUri + " , clientId = " + this.clientId + " , grantType = " + this.grantType
        + " , type = " + this.type.name() + " , grantType = " + this.grantType + " , tokenUrl = "
        + this.tokenUrl + " , authorizationUrl = " + this.authorizationUrl
        + " , this.clientAuthenticationType = " + this.clientAuthenticationType;
  }
}
