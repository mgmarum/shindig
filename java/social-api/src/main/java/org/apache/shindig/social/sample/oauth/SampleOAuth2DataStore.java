package org.apache.shindig.social.sample.oauth;

import org.apache.shindig.social.core.oauth2.AuthorizationCode;
import org.apache.shindig.social.core.oauth2.OAuth2ClientRegistration;
import org.apache.shindig.social.core.oauth2.OAuth2ClientRegistration.ClientType;
import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2Token;
import org.apache.shindig.social.core.oauth2.OAuth2Token.TokenType;
import org.apache.shindig.social.opensocial.oauth.OAuth2DataStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.inject.Singleton;

@Singleton
public class SampleOAuth2DataStore implements OAuth2DataStore {

  private List<OAuth2ClientRegistration> clients = new ArrayList<OAuth2ClientRegistration>();
  private Map<AuthorizationCode, OAuth2ClientRegistration> authCodes = 
        new HashMap<AuthorizationCode, OAuth2ClientRegistration>();
  private List<OAuth2Token> tokens = new ArrayList<OAuth2Token>();

  @Override
  public OAuth2ClientRegistration lookupClient(String clientId) {
    for (OAuth2ClientRegistration rclient : clients) {
      if(rclient.getClientId().equals(clientId)){
        return rclient;
      }
    }
    OAuth2ClientRegistration client = null;
    if(clientId != null){
      client = new OAuth2ClientRegistration();
      client.setClientId(clientId);
      //TODO Change this eventually to use real registered values and fail if client is unregistered.
      client.setClientSecret(clientId);
      client.setType(ClientType.PUBLIC);
      clients.add(client);
    }
    return client;
  }

  @Override
  public AuthorizationCode generateAuthorizationCode(OAuth2ClientRegistration client) {
    String scode = System.currentTimeMillis()+"";
    AuthorizationCode code = new AuthorizationCode(scode, client);
    authCodes.put(code, client);
    return code;
  }

  
  //TODO Using naive Auth Code, need to issue unique short lived codes per client
  @Override
  public AuthorizationCode retrieveAuthorizationCode(OAuth2ClientRegistration client, String code)
      throws OAuth2Exception {
    for (AuthorizationCode authCode : authCodes.keySet()) {
      if(authCode.getAuthCode().equals(code)){
        OAuth2ClientRegistration cl = authCodes.get(authCode);
        if(cl == client){
          return authCode;
        }
      }
    }
    throw new OAuth2Exception("Authorization code rejected");
  }

  @Override
  public OAuth2Token generateAccessToken(OAuth2ClientRegistration client) {
    OAuth2Token token = new OAuth2Token(client.getClientId() + ":" + System.currentTimeMillis());
    token.setType(TokenType.ACCESS);
    token.setClientReg(client);
    tokens.add(token);
    return token;
  }

  @Override
  public OAuth2Token generateRefreshToken(OAuth2ClientRegistration client) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public OAuth2Token generateAccessToken(OAuth2ClientRegistration client, AuthorizationCode authCode) {
    OAuth2Token token = new OAuth2Token(client.getClientId() + ":" + authCode.getAuthCode() 
        + ":" + System.currentTimeMillis());
    token.setType(TokenType.ACCESS);
    token.setClientReg(client);
    tokens.add(token);
    return token;
  }

  @Override
  public OAuth2Token retrieveToken(String token) throws OAuth2Exception {
    for (OAuth2Token otoken : tokens) {
      if(otoken.getId().equals(token)){
        return otoken;
      }
    }
    throw new OAuth2Exception("Bad token: "+ token);
  }


}
