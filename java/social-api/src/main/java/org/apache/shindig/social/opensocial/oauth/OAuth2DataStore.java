package org.apache.shindig.social.opensocial.oauth;

import org.apache.shindig.social.core.oauth2.OAuth2ClientRegistration;

public interface OAuth2DataStore {
  
  OAuth2ClientRegistration getClient(String clientId);

}
