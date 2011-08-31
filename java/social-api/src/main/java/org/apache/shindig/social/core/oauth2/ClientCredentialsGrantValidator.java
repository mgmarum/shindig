package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.social.core.oauth2.OAuth2Client.ClientType;
import org.apache.shindig.social.core.oauth2.OAuth2Client.Flow;
import org.apache.shindig.social.core.oauth2.OAuth2Types.ErrorType;

import com.google.inject.Inject;

public class ClientCredentialsGrantValidator implements OAuth2GrantValidator {

  private OAuth2DataService service;
  
  @Inject
  public ClientCredentialsGrantValidator(OAuth2DataService service){
    this.service = service;
  }

  public void setOAuth2DataService(OAuth2DataService service) {
    this.service = service;
  }
  
  public String getGrantType() {
    return "client_credentials";
  }

  public void validateRequest(OAuth2NormalizedRequest req) throws OAuth2Exception {
    OAuth2Client cl = service.getClient(req.getClientId());
    if(cl == null || cl.getFlow() != Flow.CLIENT_CREDENTIALS){
      throw new OAuth2Exception(ErrorType.ACCESS_DENIED,"Bad client id or password");
    }
    if(cl.getType() != ClientType.CONFIDENTIAL){
      throw new OAuth2Exception(ErrorType.ACCESS_DENIED,"Client credentials flow does not support public clients");
    }
    if(!cl.getSecret().equals(req.getClientSecret())){
      throw new OAuth2Exception(ErrorType.ACCESS_DENIED,"Bad client id or password");
    }

  }

}
