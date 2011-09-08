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

public interface OAuth2Context extends Serializable {
  public String getState();

  public void setState(String state);

  public String getCode();

  public void setCode(String code);

  public int getProfile();

  public void setProfile(int profile);

  public String getScope();

  public void setScope(String scope);

  public String getGadgetUri();

  public String getUser();

  public void setGadgetUri(String gadgetUri);

  public void setUser(String user);

  public void setProviderName(String providerName);

  public String getProviderName();
}
