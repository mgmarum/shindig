/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import java.io.Serializable;

/**
 * OAuth2 related data accessor
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Accessor extends Serializable {
  public enum Type {
    CONFIDENTIAL, PUBLIC, UNKNOWN
  }

  public OAuth2Token getAccessToken();

  public String getAuthorizationUrl();

  public String getClientAuthenticationType();

  public String getClientId();

  public String getClientSecret();

  public String getGadgetUri();

  public String getGrantType();

  public String getRealCallbackUrl();

  public String getRealErrorCallbackUrl();

  public String getRedirectUri();

  public OAuth2Token getRefreshToken();

  public String getScope();

  public String getServiceName();

  public String getState();

  public String getTokenUrl();

  public Type getType();

  public String getUser();

  public boolean isAllowModuleOverrides();

  public void setAccessToken(OAuth2Token accessToken);

  public void setAuthorizationUrl(String authorizationUrl);

  public void setRefreshToken(OAuth2Token refreshToken);

  public void setTokenUrl(String tokenUrl);
}
