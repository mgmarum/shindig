/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.core;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface Context {
  public OAuth2Consumer getConsumer();

  public void setConsumer(OAuth2Consumer consumer);

  public String getState();

  public void setState(String state);

  public String getCode();

  public void setCode(String code);

  public int getProfile();

  public void setProfile(int profile);

  public String getScope();

  public void setScope(String scope);

  public Token getAccessToken();

  public void setAccessToken(Token accessToken);

  public Token getRefreshToken();

  public void setRefreshToken(Token refreshToken);
}
