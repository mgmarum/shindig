package org.apache.shindig.gadgets.oauth2;

import java.io.Serializable;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.gadgets.oauth2.OAuth2Client.Flow;

public interface OAuth2CallbackState extends Serializable {
  public enum State {
    UNKNOWN, NOT_STARTED, AUTHORIZATION_REQUESTED, AUTHORIZATION_SUCCEEDED, AUTHORIZATION_FAILED, ACCESS_REQUESTED, ACCESS_FAILED, ACCESS_SUCCEEDED, REFRESH_REQUESTED, REFERESH_FAILED, REFRESH_SUCCEEDED
  }

  public State getState();

  public Flow getFlow();

  public SecurityToken getSecurityToken();

  public Integer getStateKey();

  public boolean changeState(State newState);

  public void addOAuth2StateChangeListener(OAuth2StateChangeListener listener);

  public String getAuthorizationCode();

  public OAuth2Error setAuthorizationCode(String authorizationCode) throws OAuth2RequestException;

  public String getRealCallbackUrl();

  public String getRealErrorCallbackUrl();
}
