/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import java.io.Serializable;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Client extends Serializable {
  public enum Type {
    CONFIDENTIAL, PUBLIC, UNKNOWN
  }

  public String getAuthorizationUrl();

  public String getClientAuthenticationType();

  public String getClientId();

  public String getClientSecret();

  public String getGadgetUri();

  public String getGrantType();
 
  public String getRedirectUri();

  public String getServiceName();

  public String getTokenUrl();

  public Type getType();

  public boolean isAllowModuleOverride();
  
  public void setAllowModuleOverride(boolean allowModuleOverride);
  
  public void setAuthorizationUrl(String authorizationUrl);

  public void setClientAuthenticationType(String ClientAuthenticationType);

  public void setClientId(final String clientId);
  
  public void setClientSecret(final String clientSecret) throws OAuth2EncryptionException;

  public void setGadgetUri(String gadgetUri);

  public void setGrantType(String grantType);

  public void setRedirectUri(String redirectUri);
  
  public void setServiceName(String serviceName);

  public void setTokenUrl(String tokenUrl);

  public void setType(Type type);
}
