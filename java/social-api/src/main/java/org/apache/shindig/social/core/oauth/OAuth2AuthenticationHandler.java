package org.apache.shindig.social.core.oauth;

import org.apache.shindig.auth.AuthenticationHandler;
import org.apache.shindig.auth.SecurityToken;

import javax.servlet.http.HttpServletRequest;

/** 
 * OAuth2 Authentication handler
 * **/
public class OAuth2AuthenticationHandler implements AuthenticationHandler {

  @Override
  public String getName() {
    return "OAuth2";
  }

  @Override
  public SecurityToken getSecurityTokenFromRequest(HttpServletRequest request)
      throws InvalidAuthenticationException {
    return null;
  }

  @Override
  public String getWWWAuthenticateHeader(String realm) {
    return null;
  }

}
