package org.apache.shindig.social.sample.oauth;

import org.apache.shindig.social.core.oauth2.AuthorizationCode;
import org.apache.shindig.social.core.oauth2.OAuth2ClientRegistration;
import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2Token;
import org.apache.shindig.social.core.oauth2.OAuth2ClientRegistration.ClientType;
import org.apache.shindig.social.opensocial.oauth.OAuth2DataStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SampleOAuth2DataStore implements OAuth2DataStore {

  private List<OAuth2ClientRegistration> clients = new ArrayList<OAuth2ClientRegistration>();
  private Map<AuthorizationCode, OAuth2ClientRegistration> authCodes = 
        new HashMap<AuthorizationCode, OAuth2ClientRegistration>();

  @Override
  public OAuth2ClientRegistration getClient(String clientId) {
    OAuth2ClientRegistration client = null;
    for (OAuth2ClientRegistration rclient : clients) {
      if(rclient.getClientId().equals(clientId)){
        return client;
      }
    }
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
  public void validateAuthorizationCode(OAuth2ClientRegistration client, String code)
      throws OAuth2Exception {
    OAuth2ClientRegistration cl = authCodes.get(code);
    if(cl != client){
      throw new OAuth2Exception("Authorization code rejected");
    }
    
  }

  @Override
  public OAuth2Token generateAccessToken(OAuth2ClientRegistration client) {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public OAuth2Token generateRefreshToken(OAuth2ClientRegistration client) {
    // TODO Auto-generated method stub
    return null;
  }

}
