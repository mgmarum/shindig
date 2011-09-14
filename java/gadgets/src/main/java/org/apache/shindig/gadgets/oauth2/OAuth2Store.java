/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState.State;
import org.apache.shindig.gadgets.oauth2.OAuth2Client.Flow;
import org.apache.shindig.gadgets.oauth2.OAuth2Token.Type;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Store extends OAuth2StateChangeListener {

  public boolean clearCache() throws GadgetException;

  public OAuth2CallbackState createOAuth2CallbackState(OAuth2Accessor accessor,
      OAuth2Client client, Flow flow, SecurityToken securityToken,
      HttpFetcher fetcher);

  public OAuth2Token createToken();

  public OAuth2Client getClient(String providerName, String gadgetUri)
      throws GadgetException;

  public OAuth2CallbackState getOAuth2CallbackState(Integer stateKey);

  public OAuth2Provider getProvider(String providerName) throws GadgetException;

  public OAuth2Token getToken(String providerName, String gadgetUri, String user,
      String scope, OAuth2Token.Type type) throws GadgetException;

  public boolean init() throws GadgetException;

  public OAuth2CallbackState removeOAuth2CallbackState(Integer stateKey);

  public OAuth2Token removeToken(OAuth2Token token) throws GadgetException;

  public OAuth2Token removeToken(String providerName, String gadgetUri,
      String user, String scope, Type type) throws GadgetException;

  public void setToken(OAuth2Token token) throws GadgetException;

  public void stateChange(OAuth2CallbackState state, State fromState,
      State toState);
}
