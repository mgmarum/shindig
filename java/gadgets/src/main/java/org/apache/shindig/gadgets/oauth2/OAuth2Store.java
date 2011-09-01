/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.servlet.Authority;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.oauth2.core.Consumer;
import org.apache.shindig.gadgets.oauth2.core.OAuth2ServiceProvider;
import org.apache.shindig.gadgets.oauth2.core.Token;
import org.apache.shindig.gadgets.oauth2.sample.OAuth2StoreConsumerIndex;
import org.apache.shindig.gadgets.oauth2.sample.OAuth2StoreConsumerKeyAndSecret;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public interface OAuth2Store {
  public void initFromConfigString(String oauthConfigStr) throws GadgetException;

  public void setDefaultKey(final OAuth2StoreConsumerKeyAndSecret defaultKey);

  public void setDefaultCallbackUrl(final String defaultCallbackUrl);

  public void setConsumerKeyAndSecret(final OAuth2StoreConsumerIndex providerKey,
      final OAuth2StoreConsumerKeyAndSecret keyAndSecret);

  public void setHostProvider(final com.google.inject.Provider<Authority> hostProvider);

  public Consumer getConsumerKeyAndSecret(final SecurityToken securityToken,
      final String serviceName, final OAuth2ServiceProvider provider) throws GadgetException;

  public Token getTokenInfo(final SecurityToken securityToken, final Consumer consumer,
      final String serviceName, final String tokenName) throws GadgetException;

  public void setTokenInfo(final SecurityToken securityToken, final Consumer consumer,
      final String serviceName, final String tokenName, final Token OAuth2TokenInfo)
      throws GadgetException;

  public void removeToken(final SecurityToken securityToken, final Consumer consumer,
      final String serviceName, final String tokenName) throws GadgetException;

  public int getConsumerKeyLookupCount();

  public int getAccessTokenLookupCount();

  public int getAccessTokenAddCount();

  public int getAccessTokenRemoveCount();
}
