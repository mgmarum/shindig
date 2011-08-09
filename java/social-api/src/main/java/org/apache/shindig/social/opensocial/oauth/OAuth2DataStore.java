package org.apache.shindig.social.opensocial.oauth;

import org.apache.shindig.social.core.oauth2.AuthorizationCode;
import org.apache.shindig.social.core.oauth2.OAuth2ClientRegistration;
import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2Token;

public interface OAuth2DataStore {
  
  OAuth2ClientRegistration getClient(String clientId);
  
  AuthorizationCode generateAuthorizationCode(OAuth2ClientRegistration client);
  
  void validateAuthorizationCode(OAuth2ClientRegistration client, String code) throws OAuth2Exception;
  
  OAuth2Token generateAccessToken(OAuth2ClientRegistration client);
  OAuth2Token generateRefreshToken(OAuth2ClientRegistration client);
  

}
