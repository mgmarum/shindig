package org.apache.shindig.social.core.oauth2;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.shindig.social.core.oauth2.OAuth2Client.ClientType;
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
  }

  @Override
  public OAuth2DataService getDataService() {
    return store;
  }

  @Override
  public void authenticateClient(OAuth2NormalizedRequest req) throws OAuth2Exception {
    OAuth2Client client = store.getClient(req.getClientId());
    if (client == null) throw new OAuth2Exception(ErrorType.INVALID_CLIENT, "The client is not registered.");
    String realSecret = client.getSecret();
    String reqSecret = req.getClientSecret();
    if (realSecret != null || reqSecret != null || client.getType() == ClientType.CONFIDENTIAL) {
      if (realSecret == null || reqSecret == null || !realSecret.equals(reqSecret)) {
        throw new OAuth2Exception(ErrorType.UNAUTHORIZED_CLIENT, "The client failed to authorize.");
      }
    }
  }
  
  @Override
  public void validateRequestForAuthCode(OAuth2NormalizedRequest req) throws OAuth2Exception {
    String storedURI = store.getClient(req.getClientId()).getRedirectURI();
    if (storedURI == null
        && req.getRedirectUri() == null) {
      throw new OAuth2Exception(ErrorType.INVALID_REQUEST, "No redirect_uri registered or received in request");
    }
    if(req.getRedirectUri() != null && storedURI != null){
      if(!req.getRedirectUri().equals(storedURI)){
        throw new OAuth2Exception(ErrorType.INVALID_REQUEST, "Redirect URI does not match the one registered for this client");
      }
    }
  }
  

  @Override
  public void validateRequestForAccessToken(OAuth2NormalizedRequest req)
      throws OAuth2Exception {
    if (req.getGrantType() == null) throw new OAuth2Exception(ErrorType.INVALID_GRANT, "grant_type not specified");
    for (OAuth2GrantValidator validator : validators) {
      if (validator.getGrantType().equals(req.getGrantType())) {
        validator.validateRequest(req);
        return;
      }
    }
    throw new OAuth2Exception(ErrorType.INVALID_GRANT, "Given grant_type is not supported");
  }

  @Override
  public void validateRequestForResource(OAuth2NormalizedRequest req) throws OAuth2Exception {
    OAuth2Code token = store.getAccessToken(req.getAccessToken());
    if (token == null) throw new OAuth2Exception(ErrorType.ACCESS_DENIED, "Access token is invalid.");
    if (token.getExpiration() > -1 && token.getExpiration() < System.currentTimeMillis()) {
      throw new OAuth2Exception(ErrorType.ACCESS_DENIED, "Access token has expired.");
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
  
  @SuppressWarnings("unchecked")
  public OAuth2Code generateAuthorizationCode(OAuth2NormalizedRequest req) {
    OAuth2Code authCode = new OAuth2Code();
    authCode.setValue(UUID.randomUUID().toString());
    authCode.setExpiration(System.currentTimeMillis() + AUTH_EXPIRES);
    OAuth2Client client = store.getClient(req.getString("client_id"));
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
  public OAuth2Code generateAccessToken(OAuth2NormalizedRequest req) {
    // generate token value
    OAuth2Code accessToken = new OAuth2Code();
    accessToken.setType(CodeType.ACCESS_TOKEN);
    accessToken.setValue(UUID.randomUUID().toString());
    accessToken.setExpiration(System.currentTimeMillis() + ACCESS_EXPIRES);
    
    // associate with existing authorization code
    OAuth2Code authCode = store.getAuthorizationCode(req.getClientId(), req.getAuthorizationCode());
    accessToken.setAssociatedCode(authCode);
    accessToken.setClient(authCode.getClient());
    if (authCode.getScope() != null) {
      accessToken.setScope(new ArrayList<String>(authCode.getScope()));
    }
    
    return accessToken;
  }

  @Override
  public OAuth2Code generateRefreshToken(OAuth2NormalizedRequest req) {
    throw new RuntimeException("not yet implemented");
  }
}
