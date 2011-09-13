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
  public enum Flow {
    UNKNOWN, CODE, TOKEN
  }

  public enum Type {
    UNKNOWN, CONFIDENTIAL, PUBLIC
  }

  public String getProviderName();

  public void setProviderName(String providerName);

  public String getRedirectUri();

  public void setRedirectUri(String redirectUri);

  public String getGadgetUri();

  public void setGadgetUri(String gadgetUri);

  public String getKey();

  public void setKey(String key);

  public String getSecret();

  public void setSecret(final String secret) throws OAuth2EncryptionException;

  public String getEncryptedSecret();

  public void setEncryptedSecret(String encryptedSecret) throws OAuth2EncryptionException;

  public Flow getFlow();

  public void setFlow(Flow flow);

  public Type getType();

  public void setType(Type type);
}
