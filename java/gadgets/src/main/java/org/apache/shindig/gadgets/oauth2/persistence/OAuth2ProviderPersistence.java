package org.apache.shindig.gadgets.oauth2.persistence;

import java.io.Serializable;

import org.apache.shindig.gadgets.oauth2.OAuth2Provider;

public class OAuth2ProviderPersistence implements OAuth2Provider, Serializable {
  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  private String name;
  private String authorizationUrl;
  private String tokenUrl;
  private String clientAuthenticationType;

  public String getClientAuthenticationType() {
    return this.clientAuthenticationType;
  }

  public void setClientAuthenticationType(final String clientAuthenticationType) {
    this.clientAuthenticationType = clientAuthenticationType;
  }

  public String getName() {
    return this.name;
  }

  public void setName(final String name) {
    this.name = name;
  }

  public String getAuthorizationUrl() {
    return this.authorizationUrl;
  }

  public void setAuthorizationUrl(final String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }

  public String getTokenUrl() {
    return this.tokenUrl;
  }

  public void setTokenUrl(final String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }

  @Override
  public boolean equals(final Object obj) {
    final boolean ret = false;
    if (OAuth2Provider.class.isInstance(obj)) {
      final OAuth2Provider otherProvider = (OAuth2Provider) obj;
      return this.name.equals(otherProvider.getName());
    }

    return ret;
  }

  @Override
  public int hashCode() {
    if (this.name != null) {
      return this.name.hashCode();
    }

    return 0;
  }

  @Override
  public String toString() {
    return "org.apache.shindig.gadgets.oauth2.persistence.sample.OAuth2ProviderImpl: name = "
        + this.name + " , authorizationUrl = " + this.authorizationUrl + " , tokenUrl = "
        + this.tokenUrl + " , clientAuthenticationType = " + this.clientAuthenticationType;
  }
}
