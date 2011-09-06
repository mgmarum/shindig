package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.social.core.oauth2.OAuth2Client.ClientType;
import org.apache.shindig.social.core.oauth2.OAuth2Types.CodeType;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;
import org.apache.shindig.social.core.oauth2.validators.AccessTokenRequestValidator;
import org.apache.shindig.social.core.oauth2.validators.AuthorizationCodeRequestValidator;
import org.apache.shindig.social.core.oauth2.validators.DefaultResourceRequestValidator;
import org.apache.shindig.social.core.oauth2.validators.OAuth2RequestValidator;
import org.apache.shindig.social.core.oauth2.validators.OAuth2ProtectedResourceValidator;

import javax.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.UUID;

import com.google.inject.Inject;
import com.google.inject.Singleton;

/**
 * A simple in-memory implementation of the OAuth 2 services.
 * 
 * TODO: additional auth_code use should cause invalidation of associated access_token
 * TODO: grant validators should be injected
 */
@Singleton
public class OAuth2ServiceImpl implements OAuth2Service {
  
  private OAuth2DataService store;                            // underlying OAuth data store

  
  private static final long AUTH_EXPIRES=5*60*1000;           // authorization codes expire after 5 minutes
  private static final long ACCESS_EXPIRES=5*60*60*1000;      // access tokens expire after 5 hours
  //private static final long REFRESH_EXPIRES=5*24*60*60*1000;  // authorization codes expire after 5 days
  
  @Inject
  public OAuth2ServiceImpl(OAuth2DataService store) {
    this.store = store;
    authCodeValidator = new AuthorizationCodeRequestValidator(store);
    accessTokenValidator = new AccessTokenRequestValidator(store);
    resourceReqValidator = new DefaultResourceRequestValidator(store);
  }

  public OAuth2DataService getDataService() {
    return store;
  }

  public void authenticateClient(OAuth2NormalizedRequest req) throws OAuth2Exception {
    OAuth2Client client = store.getClient(req.getClientId());
    if (client == null) {
      OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
      resp.setError(ErrorType.INVALID_CLIENT.toString());
      resp.setErrorDescription("The client ID is invalid or not registered");
      resp.setBodyReturned(true);
      resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      throw new OAuth2Exception(resp);
    }
    String realSecret = client.getSecret();
    String reqSecret = req.getClientSecret();
    if (realSecret != null || reqSecret != null || client.getType() == ClientType.CONFIDENTIAL) {
      if (realSecret == null || reqSecret == null || !realSecret.equals(reqSecret)) {
        OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
        resp.setError(ErrorType.UNAUTHORIZED_CLIENT.toString());
        resp.setErrorDescription("The client failed to authorize");
        resp.setBodyReturned(true);
        resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        throw new OAuth2Exception(resp);
      }
    }
  }
  
  private OAuth2RequestValidator authCodeValidator;
  
  public void validateRequestForAuthCode(OAuth2NormalizedRequest req) throws OAuth2Exception {
    authCodeValidator.validateRequest(req);
  }
  
  private OAuth2RequestValidator accessTokenValidator;
  
  public void validateRequestForAccessToken(OAuth2NormalizedRequest req)
      throws OAuth2Exception {
    accessTokenValidator.validateRequest(req);
  }

  
  
  private OAuth2ProtectedResourceValidator resourceReqValidator;
  
  public void validateRequestForResource(OAuth2NormalizedRequest req, Object resourceRequest) throws OAuth2Exception {
    resourceReqValidator.validateRequestForResource(req, resourceRequest);
  }
  
  public OAuth2Code grantAuthorizationCode(OAuth2NormalizedRequest req) {
    OAuth2Code authCode = generateAuthorizationCode(req);
    store.registerAuthorizationCode(req.getClientId(), authCode);
    return authCode;
  }

  public OAuth2Code grantAccessToken(OAuth2NormalizedRequest req) {
    OAuth2Code accessToken = generateAccessToken(req);
    OAuth2Code authCode = store.getAuthorizationCode(req.getClientId(), req.getAuthorizationCode());
    if(authCode != null){
      authCode.setRelatedAccessToken(accessToken);
    }
    store.registerAccessToken(req.getClientId(), accessToken);
    return accessToken;
  }

  public OAuth2Code grantRefreshToken(OAuth2NormalizedRequest req) {
    OAuth2Code refreshToken = generateRefreshToken(req);
    store.registerRefreshToken(req.getClientId(), refreshToken);
    return refreshToken;
  }
  
  /**
   * TODO: Implement scope handling
   */
  public OAuth2Code generateAuthorizationCode(OAuth2NormalizedRequest req) {
    OAuth2Code authCode = new OAuth2Code();
    authCode.setValue(UUID.randomUUID().toString());
    authCode.setExpiration(System.currentTimeMillis() + AUTH_EXPIRES);
    OAuth2Client client = store.getClient(req.getString("client_id"));
    authCode.setClient(client);
    if (req.getRedirectURI() != null) {
      authCode.setRedirectURI(req.getRedirectURI());
    } else {
      authCode.setRedirectURI(client.getRedirectURI());
    }
    return authCode;
  }

  /**
   * TODO: Implement scope handling.
   */
  public OAuth2Code generateAccessToken(OAuth2NormalizedRequest req) {
    // generate token value
    OAuth2Code accessToken = new OAuth2Code();
    accessToken.setType(CodeType.ACCESS_TOKEN);
    accessToken.setValue(UUID.randomUUID().toString());
    accessToken.setExpiration(System.currentTimeMillis() + ACCESS_EXPIRES);
    if (req.getRedirectURI() != null) {
    	accessToken.setRedirectURI(req.getRedirectURI());
    } else {
    	accessToken.setRedirectURI(store.getClient(req.getClientId()).getRedirectURI());
    }
    
    // associate with existing authorization code, if an auth code exists.
    if(req.getAuthorizationCode() != null){
      OAuth2Code authCode = store.getAuthorizationCode(req.getClientId(), req.getAuthorizationCode());
      accessToken.setRelatedAuthCode(authCode);
      accessToken.setClient(authCode.getClient());
      if (authCode.getScope() != null) {
        accessToken.setScope(new ArrayList<String>(authCode.getScope()));
      }
    }
    
    return accessToken;
  }

  public OAuth2Code generateRefreshToken(OAuth2NormalizedRequest req) {
    throw new RuntimeException("not yet implemented");
  }
}
