package org.apache.shindig.social.core.oauth2X;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.shindig.common.util.ResourceLoader;
import org.apache.shindig.protocol.ProtocolException;
import org.apache.shindig.protocol.conversion.BeanConverter;
import org.apache.shindig.social.core.oauth2X.OAuth2Types.ClientType;
import org.apache.shindig.social.core.oauth2X.OAuth2Types.ErrorType;
import org.apache.shindig.social.core.oauth2X.OAuth2Types.GrantType;
import org.json.JSONException;
import org.json.JSONObject;

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
  private Map<String, List<OAuth2Signature>> authCodes;       // authorization codes per client
  private Map<String, List<OAuth2Signature>> accessTokens;    // access tokens per client
  private Map<String, List<OAuth2Signature>> refreshTokens;   // refresh tokens per client
  private static final long AUTH_EXPIRES=5*60*1000;           // authorization codes expire after 5 minutes
  private static final long ACCESS_EXPIRES=5*60*60*1000;      // access tokens expire after 5 hours
  private static final long REFRESH_EXPIRES=5*24*60*60*1000;  // authorization codes expire after 5 days
  
  @Inject
  public OAuth2ServiceImpl(@Named("shindig.canonical.json.db")
  String jsonLocation, @Named("shindig.bean.converter.json")
  BeanConverter converter) throws Exception {
    String content = IOUtils.toString(ResourceLoader.openResource(jsonLocation), "UTF-8");
    this.oauthDB = new JSONObject(content).getJSONObject("oauth2");
    this.converter = converter;
    this.clients = new ArrayList<OAuth2Client>();
    this.authCodes = new HashMap<String, List<OAuth2Signature>>();
    this.accessTokens = new HashMap<String, List<OAuth2Signature>>();
    this.refreshTokens = new HashMap<String, List<OAuth2Signature>>();
    loadClientsFromCanonical();
  }

  public void authenticateClient(OAuth2NormalizedRequest req) {
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
  
  public void validateRequestForAuthCode(OAuth2NormalizedRequest req) {
    if (getClientById(req.getString("client_id")).getRedirectURI() == null
        && req.getString("redirect_uri") == null) {
      throw new OAuth2Exception(ErrorType.INVALID_REQUEST, "No redirect_uri registered or received in request");
    }
  }
  
  public void validateRequestForAccessToken(OAuth2NormalizedRequest req) {
    switch ((GrantType) req.get("grant_type")) {
    case AUTHORIZATION_CODE:
      if (!req.containsKey("code")) throw new OAuth2Exception(ErrorType.INVALID_REQUEST, "Missing authorization code");
      if (!req.containsKey("redirect_uri")) throw new OAuth2Exception(ErrorType.INVALID_REQUEST, "Missing redirect_uri");
      List<OAuth2Signature> clientCodes = authCodes.get(req.getString("client_id"));
      OAuth2Signature authCode = null;
      for (OAuth2Signature clientCode : clientCodes) {
        if (clientCode.getSignature().equals(req.getString("code"))) {
          authCode = clientCode;
        }
      }
      if (authCode == null) throw new OAuth2Exception(ErrorType.INVALID_GRANT, "The client does not own the authorization code");
      if (authCode.getExpiration() < System.currentTimeMillis()) throw new OAuth2Exception(ErrorType.INVALID_GRANT, "The authorization code has expired");
      if (!req.getString("redirect_uri").equals(authCode.getRedirectUri())) throw new OAuth2Exception(ErrorType.INVALID_GRANT, "redirect_uri mismatch");
      break;
    default:
      throw new RuntimeException("not yet implemented");
    }
  }

  public void validateRequestForResource(OAuth2NormalizedRequest req) {
    throw new RuntimeException("Not yet implemented");
  }
  
  @SuppressWarnings("unchecked")
  public OAuth2Signature generateAuthorizationCode(OAuth2NormalizedRequest req) {
    OAuth2Signature authCode = new OAuth2Signature();
    authCode.setSignature(UUID.randomUUID().toString());
    authCode.setExpiration(System.currentTimeMillis() + AUTH_EXPIRES);
    if (req.containsKey("scope")) authCode.setScope((List<String>) req.get("scope"));
    if (req.containsKey("redirect_uri")) {
      authCode.setRedirectUri(req.getString("redirect_uri"));
    } else {
      authCode.setRedirectUri(getClientById(req.getString("client_id")).getRedirectURI());
    }
    return authCode;
  }

  public OAuth2Signature generateAccessToken(OAuth2NormalizedRequest req) {
    OAuth2Signature accessToken = new OAuth2Signature();
    accessToken.setSignature(UUID.randomUUID().toString());
    accessToken.setExpiration(System.currentTimeMillis() + ACCESS_EXPIRES);
    
    // look up associated authorization code
    OAuth2Signature authCode = null;
    for (OAuth2Signature clientCode : authCodes.get(req.getString("client_id"))) {
      if (clientCode.getSignature().equals(req.getString("code"))) {
        authCode = clientCode;
      }
    }
    accessToken.setAssociatedSignature(authCode.getSignature());
    
    // Transfer scope to access token
    if (authCode.getScope() != null) {
      accessToken.setScope(new ArrayList<String>(authCode.getScope()));    
    }
    return accessToken;
  }

  public OAuth2Signature generateRefreshToken(OAuth2NormalizedRequest req) {
    throw new RuntimeException("not yet implemented");
  }

  public OAuth2Client getClientById(String clientId) {
    for (OAuth2Client client : clients) {
      if (client.getId().equals(clientId)) {
        return client;
      }
    }
    return null;
  }

  public void registerAuthorizationCode(String clientId, OAuth2Signature authCode) {
    if (authCodes.containsKey(clientId)) {
      ((List<OAuth2Signature>) authCodes.get(clientId)).add(authCode);
    } else {
      List<OAuth2Signature> list = new ArrayList<OAuth2Signature>();
      list.add(authCode);
      authCodes.put(clientId, list);
    }
  }

  public void unregisterAuthorizationCode(String clientId, String authCode) {
    if (authCodes.containsKey(clientId)) {
      List<OAuth2Signature> codes = authCodes.get(clientId);
      for (OAuth2Signature code : codes) {
        if (code.getSignature().equals(authCode)) {
          codes.remove(code);
          return;
        }
      }
    }
    throw new RuntimeException("signature not found");  // TODO: handle error
  }

  public void registerAccessToken(String clientId, OAuth2Signature accessToken) {
    if (accessTokens.containsKey(clientId)) {
      ((List<OAuth2Signature>) authCodes.get(clientId)).add(accessToken);
    } else {
      List<OAuth2Signature> list = new ArrayList<OAuth2Signature>();
      list.add(accessToken);
      authCodes.put(clientId, list);
    }
  }

  public void unregisterAccessToken(String clientId, String accessToken) {
    if (accessTokens.containsKey(clientId)) {
      List<OAuth2Signature> tokens = accessTokens.get(clientId);
      for (OAuth2Signature token : tokens) {
        if (token.getSignature().equals(accessToken)) {
          tokens.remove(token);
          return;
        }
      }
    }
    throw new RuntimeException("signature not found");  // TODO: handle error
  }

  public void registerRefreshToken(String clientId, OAuth2Signature refreshToken) {
    throw new RuntimeException("not yet implemented");
  }

  public void unregisterRefreshToken(String clientId, String refreshToken) {
    throw new RuntimeException("not yet implemented");
  }

  public OAuth2Signature consumeAuthorizationCode(String clientId,
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
}
