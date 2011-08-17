package org.apache.shindig.social.core.oauth2;

import org.apache.commons.io.IOUtils;
import org.apache.shindig.common.util.ResourceLoader;
import org.apache.shindig.protocol.ProtocolException;
import org.apache.shindig.protocol.conversion.BeanConverter;
import org.apache.shindig.social.core.oauth2.OAuth2Client.ClientType;
import org.apache.shindig.social.core.oauth2.OAuth2Token.TokenType;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;
import org.json.JSONException;
import org.json.JSONObject;

import javax.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.google.inject.Inject;
import com.google.inject.name.Named;

/**
 * A simple in-memory implementation of the OAuth 2 services.
 * 
 * TODO: additional auth_code use should cause invalidation of associated access_token
 */
public class OAuth2ServiceImpl implements OAuth2Service {
  
  private JSONObject oauthDB;                                 // the OAuth 2.0 JSON DB
  private BeanConverter converter;                            // the JSON<->Bean converter
  private List<OAuth2Client> clients;                         // list of clients
  private Map<String, List<OAuth2Code>> authCodes;       // authorization codes per client
  private Map<String, List<OAuth2Token>> accessTokens;    // access tokens per client
  private Map<String, List<OAuth2Token>> refreshTokens;   // refresh tokens per client
  private static final long AUTH_EXPIRES=5*60*1000;           // authorization codes expire after 5 minutes
  private static final long ACCESS_EXPIRES=5*60*60*1000;      // access tokens expire after 5 hours
  private static final long REFRESH_EXPIRES=5*24*60*60*1000;  // authorization codes expire after 5 days
  
  private AuthorizationGrantHandler[] grantHandlers = null;
  //TODO Determine mechanism for adding additional grant types.. Injection?
  public AuthorizationGrantHandler[] registerGrantHandlers(){
    grantHandlers = new AuthorizationGrantHandler[]{new AuthorizationCodeGrant(this)}; 
    return grantHandlers;
  }
  
  @Inject
  public OAuth2ServiceImpl(@Named("shindig.canonical.json.db")
  String jsonLocation, @Named("shindig.bean.converter.json")
  BeanConverter converter) throws Exception {
    String content = IOUtils.toString(ResourceLoader.openResource(jsonLocation), "UTF-8");
    this.oauthDB = new JSONObject(content).getJSONObject("oauth2");
    this.converter = converter;
    this.clients = new ArrayList<OAuth2Client>();
    this.authCodes = new HashMap<String, List<OAuth2Code>>();
    this.accessTokens = new HashMap<String, List<OAuth2Token>>();
    this.refreshTokens = new HashMap<String, List<OAuth2Token>>();
    loadClientsFromCanonical();
    registerGrantHandlers();
  }

  @Override
  public void authenticateClient(OAuth2NormalizedRequest req) throws OAuth2Exception {
    OAuth2Client client = getClientById(req.getString("client_id"));
    if (client == null) throw new OAuth2Exception(ErrorType.INVALID_CLIENT, "The client is not registered.");
    String realSecret = client.getSecret();
    String reqSecret = req.getString("client_secret");
    if (realSecret != null || reqSecret != null || client.getType() == ClientType.CONFIDENTIAL) {
      if (realSecret == null || reqSecret == null || !realSecret.equals(reqSecret)) {
        throw new OAuth2Exception(ErrorType.UNAUTHORIZED_CLIENT, "The client failed to authorize.");
      }
    }
  }
  
  @Override
  public void validateRequestForAuthCode(OAuth2NormalizedRequest req) throws OAuth2Exception {
    if (getClientById(req.getString("client_id")).getRedirectURI() == null
        && req.getString("redirect_uri") == null) {
      throw new OAuth2Exception(ErrorType.INVALID_REQUEST, "No redirect_uri registered or received in request");
    }
  }
  
//  public void validateRequestForAccessToken(OAuth2NormalizedRequest req) throws OAuth2Exception {
//    String grantType = req.getString("grant_type");
//    if(grantType != null && !grantType.equals("")){
//      for (AuthorizationGrantHandler handler : grantHandlers) {
//        if(grantType.equals(handler.getGrantType())){
//          handler.validateGrant(req);
//          return;
//        }
//      }
//      throw new OAuth2Exception(grantType + " is an unknown grant_type");
//    } else {
//      throw new OAuth2Exception("grant_type was not specified");
//    }
//    switch ((GrantType) req.get("grant_type")) {
//    case AUTHORIZATION_CODE:
//      if (!req.containsKey("code")) throw new OAuth2Exception(ErrorType.INVALID_REQUEST, "Missing authorization code");
//      if (!req.containsKey("redirect_uri")) throw new OAuth2Exception(ErrorType.INVALID_REQUEST, "Missing redirect_uri");
//      List<OAuth2Code> clientCodes = authCodes.get(req.getString("client_id"));
//      OAuth2Code authCode = null;
//      for (OAuth2Code clientCode : clientCodes) {
//        if (clientCode.getSignature().equals(req.getString("code"))) {
//          authCode = clientCode;
//        }
//      }
//      if (authCode == null) throw new OAuth2Exception(ErrorType.INVALID_GRANT, "The client does not own the authorization code");
//      if (authCode.getExpiration() < System.currentTimeMillis()) throw new OAuth2Exception(ErrorType.INVALID_GRANT, "The authorization code has expired");
//      if (!req.getString("redirect_uri").equals(authCode.getRedirectUri())) throw new OAuth2Exception(ErrorType.INVALID_GRANT, "redirect_uri mismatch");
//      break;
//    default:
//      throw new RuntimeException("not yet implemented");
//    }
//  }

  public void validateRequestForResource(OAuth2NormalizedRequest req) {
    throw new RuntimeException("Not yet implemented");
  }
  
  @SuppressWarnings("unchecked")
  public OAuth2Code generateAuthorizationCode(OAuth2NormalizedRequest req) {
    OAuth2Code authCode = new OAuth2Code();
    authCode.setValue(UUID.randomUUID().toString());
    authCode.setExpiration(System.currentTimeMillis() + AUTH_EXPIRES);
    OAuth2Client client = getClientById(req.getString("client_id"));
    authCode.setClient(client);
    if (req.containsKey("scope")) authCode.setScope((List<String>) req.get("scope"));
    if (req.containsKey("redirect_uri")) {
      authCode.setRedirectUri(req.getString("redirect_uri"));
    } else {
      authCode.setRedirectUri(client.getRedirectURI());
    }
    return authCode;
  }

  @Override
  public OAuth2Token generateAccessToken(OAuth2NormalizedRequest req) {
    OAuth2Token accessToken = new OAuth2Token();
    accessToken.setType(TokenType.ACCESS);
    accessToken.setValue(UUID.randomUUID().toString());
    accessToken.setExpiration(System.currentTimeMillis() + ACCESS_EXPIRES);
    
    // look up associated authorization code
    OAuth2Code authCode = null;
    for (OAuth2Code clientCode : authCodes.get(req.getString("client_id"))) {
      if (clientCode.getValue().equals(req.getString("code"))) {
        authCode = clientCode;
      }
    }
    accessToken.setAssociatedCode(authCode);
    accessToken.setClient(authCode.getClient());
    
    // Transfer scope to access token
    if (authCode.getScope() != null) {
      accessToken.setScope(new ArrayList<String>(authCode.getScope()));    
    }
    return accessToken;
  }

  @Override
  public OAuth2Token generateRefreshToken(OAuth2NormalizedRequest req) {
    throw new RuntimeException("not yet implemented");
  }

  @Override
  public OAuth2Client getClientById(String clientId) {
    for (OAuth2Client client : clients) {
      if (client.getId().equals(clientId)) {
        return client;
      }
    }
    return null;
  }

  public void registerAuthorizationCode(String clientId, OAuth2Code authCode) {
    if (authCodes.containsKey(clientId)) {
      ((List<OAuth2Code>) authCodes.get(clientId)).add(authCode);
    } else {
      List<OAuth2Code> list = new ArrayList<OAuth2Code>();
      list.add(authCode);
      authCodes.put(clientId, list);
    }
  }

  public void unregisterAuthorizationCode(String clientId, String authCode) {
    if (authCodes.containsKey(clientId)) {
      List<OAuth2Code> codes = authCodes.get(clientId);
      for (OAuth2Code code : codes) {
        if (code.getValue().equals(authCode)) {
          codes.remove(code);
          return;
        }
      }
    }
    throw new RuntimeException("signature not found");  // TODO: handle error
  }
  
  @Override
  public OAuth2Code retrieveAuthCode(String clientId, String codeStr) {
    if (authCodes.containsKey(clientId)) {
      List<OAuth2Code> codes = authCodes.get(clientId);
      for (OAuth2Code code : codes) {
        if (code.getValue().equals(codeStr)) {
          return code;
        }
      }
    }
    throw new RuntimeException("signature not found");  // TODO: handle error
  }
  
  @Override
  public void registerAccessToken(String clientId, OAuth2Code accessToken) {
    if (accessTokens.containsKey(clientId)) {
      ((List<OAuth2Code>) authCodes.get(clientId)).add(accessToken);
    } else {
      List<OAuth2Code> list = new ArrayList<OAuth2Code>();
      list.add(accessToken);
      authCodes.put(clientId, list);
    }
  }
  
  @Override
  public void unregisterAccessToken(String clientId, String accessToken) {
    if (accessTokens.containsKey(clientId)) {
      List<OAuth2Token> tokens = accessTokens.get(clientId);
      for (OAuth2Token token : tokens) {
        if (token.getValue().equals(accessToken)) {
          tokens.remove(token);
          return;
        }
      }
    }
    throw new RuntimeException("signature not found");  // TODO: handle error
  }

  public void registerRefreshToken(String clientId, OAuth2Code refreshToken) {
    throw new RuntimeException("not yet implemented");
  }

  public void unregisterRefreshToken(String clientId, String refreshToken) {
    throw new RuntimeException("not yet implemented");
  }
  
  @Override
  public OAuth2Token retrieveAccessToken(String clientId, String accessToken) throws OAuth2Exception {
    if (accessTokens.containsKey(clientId)) {
      List<OAuth2Token> tokens = accessTokens.get(clientId);
      for (OAuth2Token token : tokens) {
        if (token.getValue().equals(accessToken)) {
          return token;
        }
      }
    }
    return null;
  }

  public OAuth2Code consumeAuthorizationCode(String clientId,
      String authCode, String redirectUrl) {
    throw new RuntimeException("not yet implemented");
  }
  
  private void loadClientsFromCanonical() {
    for (String clientId : JSONObject.getNames(oauthDB)) {
      JSONObject clientJson;
      try {
        clientJson = oauthDB.getJSONObject(clientId).getJSONObject("registration");
        OAuth2Client client = converter.convertToObject(clientJson.toString(), OAuth2Client.class);
        client.setType(clientJson.getString("type").equals("public") ? ClientType.PUBLIC : ClientType.CONFIDENTIAL);
        clients.add(client);
      } catch (JSONException je) {
        throw new ProtocolException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, je.getMessage(), je);
      }
    }
  }

  public AuthorizationGrantHandler getAuthorizationGrantHandler(String grantType) throws OAuth2Exception {
    if(grantType != null && !grantType.equals("")){
      for (AuthorizationGrantHandler handler : grantHandlers) {
        if(grantType.equals(handler.getGrantType())){
          return handler;
        }
      }
      throw new OAuth2Exception(grantType + " is an unknown grant_type");
    } else {
      throw new OAuth2Exception("grant_type was not specified");
    }
  }

}
