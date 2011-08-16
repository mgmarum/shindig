package org.apache.shindig.social.sample.oauth;

import org.apache.shindig.common.servlet.HttpUtil;
import org.apache.shindig.common.servlet.InjectedServlet;
import org.apache.shindig.social.core.oauth2.AuthorizationCode;
import org.apache.shindig.social.core.oauth2.AuthorizationCodeGrant;
import org.apache.shindig.social.core.oauth2.AuthorizationGrantHandler;
import org.apache.shindig.social.core.oauth2.OAuth2ClientRegistration;
import org.apache.shindig.social.core.oauth2.OAuth2ClientRegistration.ClientType;
import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2Utils;
import org.apache.shindig.social.opensocial.oauth.OAuth2DataStore;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.google.inject.Inject;

/**
 * 
 * @author mgmarum
 *
 */
public class SampleOAuth2Servlet extends InjectedServlet {

  /**
   * 
   */
  private static final long serialVersionUID = -1365010221247328511L;
  private OAuth2DataStore dataStore;
  
  @Inject
  public void setDataStore(OAuth2DataStore dataStore) {
    this.dataStore = dataStore;
  }
  
  private AuthorizationGrantHandler[] grantHandlers = null;
  
  @Override
  public void init(ServletConfig config) throws ServletException {
    super.init(config);
    registerGrantHandlers();
  }

  //TODO Determine mechanism for adding additional grant types.. Injection?
  public AuthorizationGrantHandler[] registerGrantHandlers(){
    grantHandlers = new AuthorizationGrantHandler[]{new AuthorizationCodeGrant(dataStore)}; 
    return grantHandlers;
  }
  
  @Override
  protected void doGet(HttpServletRequest servletRequest,
                       HttpServletResponse servletResponse) throws ServletException, IOException {
    HttpUtil.setNoCache(servletResponse);
    String path = servletRequest.getPathInfo();
    try{
      // dispatch
      if (path.endsWith("authorize")) {
        authorizeRequest(servletRequest, servletResponse);
      } else if (path.endsWith("access_token")) {
        retreiveAccessToken(servletRequest, servletResponse);
      } else {
        servletResponse.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown URL");
      }
    } catch(OAuth2Exception ex) {
      servletResponse.sendError(HttpServletResponse.SC_FORBIDDEN, ex.getLocalizedMessage());
    }

  }

  private void authorizeRequest(HttpServletRequest servletRequest,
      HttpServletResponse servletResponse) throws IOException, OAuth2Exception{
      OAuth2ClientRegistration clientReg = getClient(servletRequest);
      validateClient(clientReg,servletRequest);
      AuthorizationResponseType rtype = 
        AuthorizationResponseType.getAuthResponseType(servletRequest);
      if(rtype != null){
        switch (rtype) {
        case TOKEN:
          // Implicit flow
          handleAccessTokenRequest(clientReg, servletRequest, servletResponse);
          break;
        case CODE:
          // Authorization Code flow
          handleAuthorizationCodeRequest(clientReg, servletRequest, servletResponse);
          break;
        default:
          servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, 
              "Unsupported response_type");
          break;
        }
      } else {
        servletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing response_type");
      }
      

    
    
  }
  
  private void handleAuthorizationCodeRequest(OAuth2ClientRegistration clientReg, 
      HttpServletRequest servletRequest, HttpServletResponse servletResponse) 
      throws OAuth2Exception {
    String redirectURI = servletRequest.getParameter("redirect_uri");
    String state = servletRequest.getParameter("state"); //Must be preserved in response
    String scope = servletRequest.getParameter("scope"); //TODO IMPLEMENT SCOPING
    Map<String, String> params = new HashMap<String, String>();

    if(redirectURI == null || redirectURI.equals("")){
      //Use default if not set in HTTP Request
      redirectURI = clientReg.getRedirectionURI();
    }
    
    //TODO Do more thorough URL validation.
    if (redirectURI == null || redirectURI.equals("") ) {
       throw new OAuth2Exception("missing redirect_uri");
    }

    
    AuthorizationCode code = dataStore.generateAuthorizationCode(clientReg);
    code.setRedirectURI(redirectURI);
    params.put("code", code.getAuthCode());
    if(state != null && !state.equals("")){
      params.put("state", state);
    }
    StringBuffer buff = new StringBuffer(redirectURI);
    if(redirectURI.contains("?")){
      buff.append('&');
    } else {
      buff.append('?');
    }
    for (String name : params.keySet()) {
      buff.append(name);
      buff.append('=');
      buff.append(params.get(name));
    }
    servletResponse.setStatus(HttpServletResponse.SC_FOUND);
    servletResponse.setHeader("Location", buff.toString());
    
  }

  private void handleAccessTokenRequest(OAuth2ClientRegistration clientReg, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
    // TODO IMPLEMENT ACCESS TOKEN REQUEST HANDLING
    servletResponse.setStatus(HttpServletResponse.SC_NOT_IMPLEMENTED);
  }


  private void validateClient(OAuth2ClientRegistration clientReg, HttpServletRequest servletRequest)
      throws OAuth2Exception {
    String clientId = servletRequest.getParameter("client_id");
    
    if(clientId.equals(clientReg.getClientId())){
      if(clientReg.getType() == ClientType.CONFIDENTIAL){
        //TODO Implement Client Authentication via BASIC auth, other pluggable client auth providers
        String clientSecret = OAuth2Utils.fetchClientSecretFromHttpRequest(clientId,servletRequest);
        if(!clientSecret.equals(clientReg.getClientSecret())){
          throw new OAuth2Exception("Unknown OAuth 2 client \"" + clientId + "\"");
        }
      }
    }
    
  }


  private OAuth2ClientRegistration getClient(HttpServletRequest req) throws OAuth2Exception{
    String clientId = req.getParameter("client_id");
    //TODO can client_id be passed via BASIC auth?
    OAuth2ClientRegistration clientReg = dataStore.lookupClient(clientId);
    if(clientReg == null){
      throw new OAuth2Exception(clientId + " is not registered with OAuth2 provider");
    }
    return clientReg;
  }


  private void retreiveAccessToken(HttpServletRequest servletRequest,
      HttpServletResponse servletResponse) throws OAuth2Exception{
    String grantType = servletRequest.getParameter("grant_type");
    if(grantType != null && !grantType.equals("")){
      for (AuthorizationGrantHandler handler : grantHandlers) {
        if(grantType.equals(handler.getGrantType())){
          handler.validateGrant(servletRequest, servletResponse);
          return;
        }
      }
      throw new OAuth2Exception(grantType + " is an unknown grant_type");
    } else {
      throw new OAuth2Exception("grant_type was not specified");
    }

    //TODO IMPLEMENT ACCESS TOKEN SERVLET, expect an Authentication Code or Refresh Token
    
  }
  
  public enum AuthorizationResponseType{
    TOKEN("token"), CODE("code");
    
    private String pValue;
    
    private AuthorizationResponseType(String paramValue){
      pValue = paramValue;
    }
    
    @Override
    public String toString() {
      return pValue;
    }
    
    public static AuthorizationResponseType getAuthResponseType(ServletRequest req){
      String requestValue = req.getParameter("response_type");
      if(requestValue != null){
        if(requestValue.equalsIgnoreCase("token")){
          return TOKEN;
        } else if (requestValue.equalsIgnoreCase("code")){
          return CODE;
        }
      }
      return null;
    }
  }

}
