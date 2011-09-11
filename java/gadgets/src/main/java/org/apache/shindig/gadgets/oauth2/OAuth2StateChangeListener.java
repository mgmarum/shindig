package org.apache.shindig.gadgets.oauth2;

public interface OAuth2StateChangeListener {
  public void stateChange(OAuth2CallbackState state, OAuth2CallbackState.State fromState,
      OAuth2CallbackState.State toState);
}
