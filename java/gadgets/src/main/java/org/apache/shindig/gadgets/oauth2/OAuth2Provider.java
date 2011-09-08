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

public interface OAuth2Provider extends Serializable {
  public String getName();

  public void setName(String name);

  public String getAuthorizationUrl();

  public void setAuthorizationUrl(String authorizationUrl);

  public String getTokenUrl();

  public void setTokenUrl(String tokenUrl);

  public int getSupportedProfiles();

  public void setSupportedProfiles(int supportedProfiles);

}