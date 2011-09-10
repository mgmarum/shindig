package org.apache.shindig.gadgets.oauth2.sample;

import java.util.HashSet;
import java.util.Set;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2StateChangeListener;
import org.apache.shindig.gadgets.oauth2.OAuth2Client.Flow;

public class OAuth2CallbackStateImpl implements OAuth2CallbackState {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  private final Integer stateKey;
  private final Flow flow;
  private final String realCallbackUrl;
  private final String errorCallback;
  private final SecurityToken securityToken;
  private final Set<OAuth2StateChangeListener> listeners;
  private State state;
  private static int STATE_KEY_COUNT = 0;

  public OAuth2CallbackStateImpl(final Flow flow, final SecurityToken securityToken, final String realCallbackUrl, final String errorCallbackUrl) {
    this.state = State.NOT_STARTED;
    OAuth2CallbackStateImpl.STATE_KEY_COUNT++;
    this.stateKey = new Integer(OAuth2CallbackStateImpl.STATE_KEY_COUNT);
    this.flow = flow;
    this.securityToken = securityToken;
    this.realCallbackUrl = realCallbackUrl;
    this.errorCallback = errorCallbackUrl;
    this.listeners = new HashSet<OAuth2StateChangeListener>(1);
  }
  
  public void invalidate() {
    this.state = State.UNKNOWN;
    this.listeners.clear();
  }

  public Integer getStateKey() {
    return stateKey;
  }

  public Flow getFlow() {
    return flow;
  }

  public String getRealCallbackUrl() {
    return realCallbackUrl;
  }

  public String getErrorCallback() {
    return errorCallback;
  }

  public SecurityToken getSecurityToken() {
    return securityToken;
  }

  public Set<OAuth2StateChangeListener> getListeners() {
    return listeners;
  }

  public State getState() {
    return state;
  }

  public void addOAuth2StateChangeListener(OAuth2StateChangeListener listener) {
    this.listeners.add(listener);
  }

  public boolean changeState(State newState) {
    // TODO ARC, should we have state change validation and listener veto?
    synchronized (this) {
      final State oldState = this.state;
      for (final OAuth2StateChangeListener listener : this.listeners) {
        listener.stateChange(this, oldState, newState);
      }
      this.state = newState;
    }

    return true;
  }
  
  @Override
  public int hashCode() {
    return this.stateKey.intValue();
  }
  
  @Override
  public boolean equals(Object other) {
    if (other != null) {
      if (OAuth2CallbackStateImpl.class.isInstance(other)) {
        return this.hashCode() == other.hashCode();
      }
    }
    
    return false;
  }
}
