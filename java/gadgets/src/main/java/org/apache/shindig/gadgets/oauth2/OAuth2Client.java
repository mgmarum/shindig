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

  public String getGadgetUri();

  public String getKey();

  public String getProviderName();

  public String getRedirectUri();

  public String getSecret();

  public Type getType();

  public void setGadgetUri(String gadgetUri);

  public void setKey(String key);

  public void setProviderName(String providerName);

  public void setRedirectUri(String redirectUri);

  public void setSecret(final String secret) throws OAuth2EncryptionException;

  public void setType(Type type);
  
  public void setGrantType(String grantType);
  
  public String getGrantType();
}
