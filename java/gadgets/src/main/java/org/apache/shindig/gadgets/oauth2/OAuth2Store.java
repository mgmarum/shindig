/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.gadgets.GadgetException;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Store {

  public boolean clearCache() throws GadgetException;

  public OAuth2Token createToken();

  public OAuth2Accessor getOAuth2Accessor(Integer index);

  public OAuth2Accessor getOAuth2Accessor(String gadgetUri, String serviceName, String user,
      String scope) throws GadgetException;

  public Integer getOAuth2AccessorIndex(String gadgetUri, String serviceName, String user,
      String scope);

  public OAuth2Token getToken(String gadgetUri, String serviceName, String user, String scope,
      OAuth2Token.Type type) throws GadgetException;

  public boolean init() throws GadgetException;

  public OAuth2Accessor removeOAuth2Accessor(OAuth2Accessor accessor);

  public OAuth2Token removeToken(OAuth2Token token) throws GadgetException;

  public void setToken(OAuth2Token token) throws GadgetException;

  public void storeOAuth2Accessor(OAuth2Accessor accessor);
}
