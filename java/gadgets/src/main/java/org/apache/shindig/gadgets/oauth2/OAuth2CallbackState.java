package org.apache.shindig.gadgets.oauth2;

import java.io.Serializable;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.gadgets.oauth2.OAuth2Client.Flow;


public interface OAuth2CallbackState extends Serializable {
  public enum State {
    UNKNOWN, NOT_STARTED, AUTHORIZATION_REQUESTED, AUTHORIZATION_SUCCEEDED, AUTHORIZATION_FAILED, ACCESS_REQUESTED, ACCESS_FAILED, REFRESH_REQUESTED, REFERESH_FAILED
  }
  public State getState();
  public Flow getFlow();
  public String getRealCallbackUrl();
  public String getErrorCallback();
  public SecurityToken getSecurityToken(); 
  public void addOAuth2StateChangeListener(OAuth2StateChangeListener listener);
  public Integer getStateKey();
  public boolean changeState(State newState);
}

