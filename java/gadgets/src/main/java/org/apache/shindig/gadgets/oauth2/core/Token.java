/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.core;

import java.util.Date;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface Token {
  public static enum TokenType {
  }

  public TokenType getType();

  public void setType(TokenType type);

  public String getToken();

  public void setToken(String token);

  public String getSecret();

  public void setSecret(String secret);

  public Date getExpiration();

  public void setExpiration(Date expiration);

  public String getAccessToken();

  public String getSessionHandle();

  public long getTokenExpireMillis();
}
