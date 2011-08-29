package org.apache.shindig.social.core.oauth2;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.social.core.oauth2.OAuth2Types.TokenFormat;

/**
 * NOTE: I plan to bloat handle(), then re-factor into a "logic-tree" later... This is where it all comes together!!!
 * 
 * TODO: If 'Authorization' header used, must reply with WWW something
 */
public class OAuth2AuthorizationHandler {
  
  private OAuth2Service service;
  
  public OAuth2AuthorizationHandler(OAuth2Service service) {
    this.service = service;
  }
  
  public OAuth2NormalizedResponse handle(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {   
    try {
      // normalize the request
      OAuth2NormalizedRequest normalizedReq = new OAuth2NormalizedRequest(request);
      System.out.println("Normalized token request: ");
      System.out.println(normalizedReq.toString());
      
      // process request according to flow
      OAuth2NormalizedResponse normalizedResp = new OAuth2NormalizedResponse();
      if (normalizedReq.getResponseType() != null) {
        switch (normalizedReq.getEnumeratedResponseType()) {
        case CODE:
          // authorization code flow
          service.validateRequestForAuthCode(normalizedReq);
          OAuth2Code authCode = service.grantAuthorizationCode(normalizedReq);
          
          // send response
          normalizedResp.setCode(authCode.getValue());
          if (normalizedReq.getState() != null) normalizedResp.setState(normalizedReq.getState());
          normalizedResp.setHeader("Location", OAuth2Utils.buildUrl(authCode.getRedirectUri(), normalizedResp.getResponseParameters(), null));
          normalizedResp.setStatus(HttpServletResponse.SC_FOUND);
          normalizedResp.setBodyReturned(false);
          return normalizedResp;
        case TOKEN:
          // implicit flow
          service.validateRequestForAccessToken(normalizedReq);
          OAuth2Code accessToken = service.grantAccessToken(normalizedReq);
          
          // send response
          normalizedResp.setAccessToken(accessToken.getValue());
          normalizedResp.setTokenType(TokenFormat.BEARER.toString());
          normalizedResp.setExpiresIn((accessToken.getExpiration() - System.currentTimeMillis()) + "");
          if (normalizedReq.getState() != null) normalizedResp.setState(normalizedReq.getState());
          normalizedResp.setHeader("Location", OAuth2Utils.buildUrl(accessToken.getRedirectUri(), null, normalizedResp.getResponseParameters()));
          normalizedResp.setStatus(HttpServletResponse.SC_FOUND);
          normalizedResp.setBodyReturned(false);
          return normalizedResp;
        default:
          // TODO: formulate normalized response with error and send
          break;
        }
      }
    } catch(OAuth2Exception oae) {
      return oae.getNormalizedResponse();
    }
    
    return null;  // should never reach this, otherwise prepare for a NPE
  }
}
