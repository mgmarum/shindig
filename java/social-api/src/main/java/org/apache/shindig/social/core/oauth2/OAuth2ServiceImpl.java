package org.apache.shindig.social.core.oauth2;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.social.core.oauth2.OAuth2Client.ClientType;
import org.apache.shindig.social.core.oauth2.OAuth2Client.Flow;
import org.apache.shindig.social.core.oauth2.OAuth2Types.CodeType;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;

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
  private List<OAuth2GrantValidator> validators;              // grant validators
  private static final long AUTH_EXPIRES=5*60*1000;           // authorization codes expire after 5 minutes
  private static final long ACCESS_EXPIRES=5*60*60*1000;      // access tokens expire after 5 hours
  //private static final long REFRESH_EXPIRES=5*24*60*60*1000;  // authorization codes expire after 5 days
  
  @Inject
  public OAuth2ServiceImpl(OAuth2DataService store) {
    this.store = store;
    this.validators  = new ArrayList<OAuth2GrantValidator>();
    validators.add(new AuthCodeGrantValidator(store));
    validators.add(new ClientCredentialsGrantValidator(store));
  }

  @Override
  public OAuth2DataService getDataService() {
    return store;
  }

  @Override
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
  
  @Override
  public void validateRequestForAuthCode(OAuth2NormalizedRequest req) throws OAuth2Exception {
    OAuth2Client client = store.getClient(req.getClientId());
    if(client == null) {
      OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
      resp.setError(ErrorType.INVALID_REQUEST.toString());
      resp.setErrorDescription("The client is invalid or not registered");
      resp.setBodyReturned(true);
      resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
      throw new OAuth2Exception(resp);
    }
    String storedURI = client.getRedirectURI();
    if (storedURI == null && req.getRedirectURI() == null) {
      OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
      resp.setError(ErrorType.INVALID_REQUEST.toString());
      resp.setErrorDescription("No redirect_uri registered or received in request");
      resp.setBodyReturned(true);
      resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
      throw new OAuth2Exception(resp);
    }
    if(req.getRedirectURI() != null && storedURI != null){
      if(!req.getRedirectURI().equals(storedURI)){
        OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
        resp.setError(ErrorType.INVALID_REQUEST.toString());
        resp.setErrorDescription("Redirect URI does not match the one registered for this client");
        resp.setBodyReturned(true);
        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
        throw new OAuth2Exception(resp);
      }
    }
  }
  

  @Override
  public void validateRequestForAccessToken(OAuth2NormalizedRequest req)
      throws OAuth2Exception {
    if (req.getGrantType() != null) {
      for (OAuth2GrantValidator validator : validators) {
        if (validator.getGrantType().equals(req.getGrantType())) {
          validator.validateRequest(req);
          return; // request validated
        }
      }
      OAuth2NormalizedResponse response = new OAuth2NormalizedResponse();
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      response.setError(ErrorType.UNSUPPORTED_GRANT_TYPE.toString());
      response.setErrorDescription("Unsupported grant type");
      response.setBodyReturned(true);
      throw new OAuth2Exception(response);
    } else {  // implicit flow does not include grant type
      if (req.getResponseType() == null || !req.getResponseType().equals("token")) {
        throw new OAuth2Exception(ErrorType.UNSUPPORTED_RESPONSE_TYPE, "Unsupported response type");
      }
      OAuth2Client client = store.getClient(req.getClientId());
      if(client == null || client.getFlow() != Flow.IMPLICIT){
        OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
        resp.setError(ErrorType.INVALID_CLIENT.toString());
        resp.setErrorDescription(req.getClientId()+" is not a registered implicit client");
        resp.setBodyReturned(true);
        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
        throw new OAuth2Exception(resp);
      }
      if (req.getRedirectURI() == null && client.getRedirectURI() == null) {
        OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
        resp.setError(ErrorType.INVALID_REQUEST.toString());
        resp.setErrorDescription("NO redirect_uri registered or received in request");
        resp.setBodyReturned(true);
        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
        throw new OAuth2Exception(resp);
      }
      if (req.getRedirectURI() != null &&
          !req.getRedirectURI().equals(client.getRedirectURI())) {
        OAuth2NormalizedResponse resp = new OAuth2NormalizedResponse();
        resp.setError(ErrorType.INVALID_REQUEST.toString());
        resp.setErrorDescription("Redirect URI does not match the one registered for this client");
        resp.setBodyReturned(true);
        resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
        throw new OAuth2Exception(resp);
      }
      return; // request validated
    }
  }

  /**
   * TODO: implement scope handling.
   */
  @Override
  public void validateRequestForResource(OAuth2NormalizedRequest req, String requestedResource) throws OAuth2Exception {
    OAuth2Code token = store.getAccessToken(req.getAccessToken());
    if (token == null) throw new OAuth2Exception(ErrorType.ACCESS_DENIED, "Access token is invalid.");
    if (token.getExpiration() > -1 && token.getExpiration() < System.currentTimeMillis()) {
      throw new OAuth2Exception(ErrorType.ACCESS_DENIED, "Access token has expired.");
    }
    if (requestedResource != null) {
      // TODO: validate that requested resource is within scope
    }
  }
  
  @Override
  public OAuth2Code grantAuthorizationCode(OAuth2NormalizedRequest req) {
    OAuth2Code authCode = generateAuthorizationCode(req);
    store.registerAuthorizationCode(req.getClientId(), authCode);
    return authCode;
  }

  @Override
  public OAuth2Code grantAccessToken(OAuth2NormalizedRequest req) {
    OAuth2Code accessToken = generateAccessToken(req);
    store.registerAccessToken(req.getClientId(), accessToken);
    return accessToken;
  }

  @Override
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
  @Override
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
      accessToken.setAssociatedCode(authCode);
      accessToken.setClient(authCode.getClient());
      if (authCode.getScope() != null) {
        accessToken.setScope(new ArrayList<String>(authCode.getScope()));
      }
    }
    
    return accessToken;
  }

  @Override
  public OAuth2Code generateRefreshToken(OAuth2NormalizedRequest req) {
    throw new RuntimeException("not yet implemented");
  }
}
