package org.apache.shindig.social.core.oauth2;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.social.core.oauth2.OAuth2Types.TokenFormat;

/**
 * TODO: what does token_type = bearer|mac mean for subsequent requests?  Might have to add type to Signature, etc
 * TODO: generate refreshToken & associate with accessToken
 */
public class OAuth2TokenHandler {
  
  private OAuth2Service service;
  
  public OAuth2TokenHandler(OAuth2Service service) {
    this.service = service;
  }

  public void handle(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    try {
      // normalize the request
      OAuth2NormalizedRequest normalizedReq = new OAuth2NormalizedRequest(request);
      System.out.println("Normalized token request: ");
      System.out.println(normalizedReq.toString());
      
      // grant access token
      service.authenticateClient(normalizedReq);
      service.validateRequestForAccessToken(normalizedReq);
      OAuth2Code accessToken = service.grantAccessToken(normalizedReq);
      
      // send response
      OAuth2NormalizedResponse normalizedResp = new OAuth2NormalizedResponse();
      normalizedResp.setAccessToken(accessToken.getValue());
      normalizedResp.setTokenType(TokenFormat.BEARER.toString());
      normalizedResp.setExpiresIn((accessToken.getExpiration() - System.currentTimeMillis() + ""));
      normalizedResp.setScope(listToString(accessToken.getScope()));
      normalizedResp.setStatus(HttpServletResponse.SC_OK);
      normalizedResp.setBodyReturned(true);
      if (normalizedReq.getState() != null) normalizedResp.setState(normalizedReq.getState());
      OAuth2Utils.sendOAuth2Response(response, normalizedResp);
    } catch(OAuth2Exception oae) {
      OAuth2Utils.sendOAuth2Response(response, oae.getNormalizedResponse());
    }
  }
  
  /**
   * Private utility to comma-delimit a list of Strings
   */
  private static String listToString(List<String> list) {
    if (list == null || list.isEmpty()) return "";
    StringBuilder sb = new StringBuilder();
    for (String item : list) {
     sb.append(item);
     sb.append(',');
    }
    sb.deleteCharAt(sb.length());
    return sb.toString();
  }
}
