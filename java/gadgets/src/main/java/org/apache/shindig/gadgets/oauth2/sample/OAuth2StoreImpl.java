/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.sample;

import java.net.URI;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.servlet.Authority;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;
import org.apache.shindig.gadgets.oauth2.core.OAuth2Consumer;
import org.apache.shindig.gadgets.oauth2.core.OAuth2ServiceProvider;
import org.apache.shindig.gadgets.oauth2.core.Token;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Persistence;

import com.google.common.collect.Maps;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2StoreImpl implements OAuth2Store {
  private static final String LOG_CLASS = OAuth2StoreImpl.class.getName();
  private static final Level LOG_LEVEL = Level.FINER;
  private static final Logger LOGGER = Logger.getLogger(OAuth2StoreImpl.LOG_CLASS);

  private final Map<OAuth2StoreConsumerIndex, OAuth2StoreConsumerKeyAndSecret> consumers;

  private final Map<OAuth2StoreTokenIndex, Token> tokens;

  /**
   * Key to use when no other key is found.
   */
  private OAuth2StoreConsumerKeyAndSecret defaultKey;

  private String defaultCallbackUrl;

  private int consumerKeyLookupCount = 0;

  private int accessTokenLookupCount = 0;

  private int accessTokenAddCount = 0;

  private int accessTokenRemoveCount = 0;

  private com.google.inject.Provider<Authority> hostProvider;

  private final OAuth2Persistence persister;

  public OAuth2StoreImpl(final OAuth2Persistence persister) {
    final boolean bIsLogging = OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL);

    this.consumers = Maps.newHashMap();
    this.tokens = Maps.newHashMap();

    this.persister = persister;
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.log(OAuth2StoreImpl.LOG_LEVEL, "persister = {0}", persister);
    }
  }

  public void initFromConfigString(final String oauthConfigStr) throws GadgetException {
    // try {
    // JSONObject oauthConfigs = new JSONObject(oauthConfigStr);
    // for (Iterator<?> i = oauthConfigs.keys(); i.hasNext();) {
    // String url = (String) i.next();
    // URI gadgetUri = new URI(url);
    // JSONObject oauthConfig = oauthConfigs.getJSONObject(url);
    // storeConsumerInfos(gadgetUri, oauthConfig);
    // }
    // } catch (JSONException e) {
    // throw new GadgetException(GadgetException.Code.OAUTH_STORAGE_ERROR, e);
    // } catch (URISyntaxException e) {
    // throw new GadgetException(GadgetException.Code.OAUTH_STORAGE_ERROR, e);
    // }
  }

  private void storeConsumerInfo(final URI gadgetUri, final String serviceName,
      final OAuth2Consumer consumer) throws GadgetException {
    this.realStoreConsumerInfo(gadgetUri, serviceName, consumer);
  }

  private void realStoreConsumerInfo(final URI gadgetUri, final String serviceName,
      final OAuth2Consumer consumer) {
    // final String callbackUrl = consumer.getCallbackUrl();
    // String consumerSecret = consumer.getConsumerSecret();
    // final String consumerKey = consumer.getConsumerKey();
    // final String OAuth2KeyTypeStr = consumer.getOAuth2KeyType();
    // OAuth2KeyType OAuth2KeyType = OAuth2KeyType.HMAC_SYMMETRIC;
    //
    // if ("RSA_PRIVATE".equals(OAuth2KeyTypeStr)) {
    // OAuth2KeyType = OAuth2KeyType.RSA_PRIVATE;
    // consumerSecret = OAuth2Store.convertFromOpenSsl(consumerSecret);
    // }
    //
    // final OAuth2StoreConsumerKeyAndSecret kas = new
    // OAuth2StoreConsumerKeyAndSecret(consumerKey,
    // consumerSecret, OAuth2KeyType, null, callbackUrl);
    //
    // final OAuth2StoreConsumerIndex index = new OAuth2StoreConsumerIndex();
    // index.setGadgetUri(gadgetUri.toASCIIString());
    // index.setServiceName(serviceName);
    // this.setConsumerKeyAndSecret(index, kas);
  }

  // Support standard openssl keys by stripping out the headers and blank lines
  public static String convertFromOpenSsl(final String privateKey) {
    return privateKey.replaceAll("-----[A-Z ]*-----", "").replace("\n", "");
  }

  public void setDefaultKey(final OAuth2StoreConsumerKeyAndSecret defaultKey) {
    if (OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL)) {
      OAuth2StoreImpl.LOGGER.log(OAuth2StoreImpl.LOG_LEVEL, "this.defaultKey = {0}", defaultKey);
    }

    this.defaultKey = defaultKey;
  }

  public void setDefaultCallbackUrl(final String defaultCallbackUrl) {
    if (OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL)) {
      OAuth2StoreImpl.LOGGER.log(OAuth2StoreImpl.LOG_LEVEL, "this.defaultCallbackUrl = {0}",
          defaultCallbackUrl);
    }

    this.defaultCallbackUrl = defaultCallbackUrl;
  }

  public void setConsumerKeyAndSecret(final OAuth2StoreConsumerIndex providerKey,
      final OAuth2StoreConsumerKeyAndSecret keyAndSecret) {
    this.consumers.put(providerKey, keyAndSecret);
  }

  public void setHostProvider(final com.google.inject.Provider<Authority> hostProvider) {
    if (OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL)) {
      OAuth2StoreImpl.LOGGER
          .log(OAuth2StoreImpl.LOG_LEVEL, "this.hostProvider = {0}", hostProvider);
    }

    this.hostProvider = hostProvider;
  }

  public OAuth2Consumer getConsumerKeyAndSecret(final SecurityToken securityToken,
      final String serviceName, final OAuth2ServiceProvider provider) throws GadgetException {
    final boolean bIsLogging = OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL);
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.entering(OAuth2StoreImpl.LOG_CLASS,
          "getConsumerKeyAndSecret(securityToken, serviceName, provider)", new Object[] {
              securityToken, serviceName, provider });
    }
    ++this.consumerKeyLookupCount;
    final OAuth2StoreConsumerIndex pk = new OAuth2StoreConsumerIndex();
    pk.setGadgetUri(securityToken.getAppUrl());
    pk.setServiceName(serviceName);
    OAuth2StoreConsumerKeyAndSecret cks = this.consumers.get(pk);

    // if (cks == null) {
    // final Provider vulcanProvider =
    // this.persister.findProviderByName(serviceName);
    // if (bIsLogging) {
    // if (vulcanProvider != null) {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL,
    // "vulcanProvider = {0} : {1}", new Object[] {
    // vulcanProvider.getName(), vulcanProvider });
    // } else {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "vulcanProvider is NULL");
    // }
    // }
    // if (vulcanProvider != null) {
    // Client client = null;
    // client = this.persister.findClientByProviderId(vulcanProvider);
    // if (bIsLogging) {
    // if (client != null) {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "client = {0}", client);
    // } else {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "client is NULL");
    // }
    // }
    // Token token = null;
    // token = this.persister.findTokenById(client.getToken().getId());
    // if (bIsLogging) {
    // if (token != null) {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "token = {0}", token);
    // } else {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "token is NULL");
    // }
    // }
    // if (bIsLogging) {
    // if (token != null) {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "token = {0}", token);
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "token.getToken = {0}",
    // token.getToken());
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "token.getSecret = {0}",
    // token.getSecret());
    // try {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL,
    // "token.getEncryptedSecret = {0}",
    // token.getEncryptedSecret());
    // } catch (final Exception exception) {
    // }
    // } else {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "token is NULL");
    // }
    // }
    //
    // String callback = client.getCallbackurl();
    // if ((callback == null) || ("OAuthCallback".equals(callback))) {
    // callback = this.defaultCallbackUrl;
    // }
    //
    // if (this.hostProvider != null) {
    // callback = callback.replace("%authority%",
    // this.hostProvider.get().getAuthority());
    // }
    //
    // if (bIsLogging) {
    // LOGGER.log(LOG_LEVEL, "callback = {0}", callback);
    // }
    //
    // try {
    // final Consumer consumer = new Consumer(callback, token.getSecret(),
    // token.getToken(),
    // OAuth2KeyType.HMAC_SYMMETRIC.name());
    // this.storeConsumerInfo(new URI(securityToken.getAppUrl()), serviceName,
    // consumer);
    // } catch (final URISyntaxException e) {
    // }
    // }
    //
    // cks = this.consumers.get(pk);
    // }

    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.log(OAuth2StoreImpl.LOG_LEVEL, "cks = {0}", cks);
    }

    if (cks == null) {
      cks = this.defaultKey;
    }

    if (cks == null) {
      throw new GadgetException(GadgetException.Code.INTERNAL_SERVER_ERROR, "No key for gadget "
          + securityToken.getAppUrl() + " and service " + serviceName);
    }

    String callback = cks.getCallbackUrl();
    if ((callback == null) || ("OAuthCallback".equals(callback))) {
      callback = this.defaultCallbackUrl;
    }

    if (this.hostProvider != null) {
      callback = callback.replace("%authority%", this.hostProvider.get().getAuthority());
    }

    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.log(OAuth2StoreImpl.LOG_LEVEL, "callback = {0}", callback);
    }

    final OAuth2StoreConsumerIndex pk2 = new OAuth2StoreConsumerIndex();
    pk2.setGadgetUri(securityToken.getAppUrl());
    pk2.setServiceName(serviceName);
    cks = this.consumers.get(pk2);

    // OAuthConsumer consumer = null;
    // if (cks.getOAuth2KeyType() == OAuth2KeyType.RSA_PRIVATE) {
    // consumer = new OAuthConsumer(callback, cks.getConsumerKey(), null,
    // provider);
    // // The oauth.net java code has lots of magic. By setting this property
    // here, code thousands
    // // of lines away knows that the consumerSecret value in the consumer
    // should be treated as
    // // an RSA private key and not an HMAC key.
    // consumer.setProperty(OAuth.OAUTH_SIGNATURE_METHOD, OAuth.RSA_SHA1);
    // consumer.setProperty(RSA_SHA1.PRIVATE_KEY, cks.getConsumerSecret());
    // } else {
    // consumer = new OAuthConsumer(callback, cks.getConsumerKey(),
    // cks.getConsumerSecret(), provider);
    // consumer.setProperty(OAuth.OAUTH_SIGNATURE_METHOD, OAuth.HMAC_SHA1);
    // }

    // final ConsumerInfo ret = new ConsumerInfo(consumer, cks.getKeyName(),
    // callback);

    final OAuth2Consumer ret = null;

    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.exiting(OAuth2StoreImpl.LOG_CLASS,
          "getConsumerKeyAndSecret(securityToken, serviceName, provider)", ret);
    }

    return ret;
  }

  public Token getTokenInfo(final SecurityToken securityToken, final OAuth2Consumer consumer,
      final String serviceName, final String tokenName) {
    final boolean bIsLogging = OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL);
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.entering(OAuth2StoreImpl.LOG_CLASS,
          "securityToken = {0}, consumer = {1}, serviceName = {2}, tokenName = {3}", new Object[] {
              securityToken, consumer, serviceName, tokenName });
    }
    ++this.accessTokenLookupCount;

    final OAuth2StoreTokenIndex tokenIndex = this.createTokenIndex(securityToken, serviceName,
        tokenName);

    final Token ret = this.tokens.get(tokenIndex);
    // if (ret == null) {
    // final Context context = this.persister.findContext(serviceName,
    // this.getUser(securityToken));
    // if (context != null) {
    // final OAuthAccessor accessor = this.getOAuthAccessor(context);
    // final Date expiration = context.getExpiration();
    // long time;
    // if (expiration != null) {
    // time = expiration.getTime();
    // } else {
    // time = 0L;
    // }
    // ret = new OAuth2TokenInfo(accessor.accessToken, context
    // .getToken().getSecret(), context.getSessionhandle(), time);
    // this.setOAuth2TokenInfo(securityToken, consumer, serviceName,
    // tokenName, ret);
    // }
    // }
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.exiting(OAuth2StoreImpl.LOG_CLASS,
          "getTokenInfo(securityToken, consumer, serviceName, tokenName)", ret);
    }
    return ret;
  }

  public void setTokenInfo(final SecurityToken securityToken, final OAuth2Consumer consumer,
      final String serviceName, final String tokenName, final Token token) {
    final boolean bIsLogging = OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL);
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.entering(OAuth2StoreImpl.LOG_CLASS,
          "setTokenInfo(securityToken, consumer, serviceName, tokenName, Token)", new Object[] {
              securityToken, consumer, serviceName, tokenName, token });
    }
    ++this.accessTokenAddCount;
    final OAuth2StoreTokenIndex tokenIndex = this.createTokenIndex(securityToken, serviceName,
        tokenName);
    this.tokens.put(tokenIndex, token);
    final String user = this.getUser(securityToken);
    // Context ctx = null;
    // ctx = this.persister.findAuthorizedContext(user, serviceName);
    // boolean createContext = false;
    // boolean createToken = false;
    // if (ctx == null) {
    // ctx = this.persister.newContext();
    // ctx.setId(UUID.randomUUID().toString());
    // ctx.setUserid(user);
    // final Client client =
    // this.persister.findClientByProviderName(serviceName);
    // ctx.setClient(client);
    // createContext = true;
    // }
    // Token token = ctx.getToken();
    // if (token == null) {
    // try {
    // token = this.persister.newToken();
    // token.setId(UUID.randomUUID().toString());
    // ctx.setToken(token);
    // createToken = true;
    // } catch (final Exception e) {
    // OAuth2Store.LOGGER.log(OAuth2Store.LOG_LEVEL, "Failed to create Token",
    // e);
    // return;
    // }
    // }
    // token.setToken(OAuth2TokenInfo.getAccessToken());
    // token.setSecret(OAuth2TokenInfo.getTokenSecret());
    // token.setExpiration(new
    // Timestamp(OAuth2TokenInfo.getTokenExpireMillis()));
    // ctx.setAuthorized(1);
    // ctx.setSessionhandle(OAuth2TokenInfo.getSessionHandle());
    // if (createToken) {
    // this.persister.insertToken(token);
    // } else {
    // this.persister.updateToken(token);
    // }
    // if (createContext) {
    // this.persister.insertContext(ctx);
    // } else {
    // this.persister.updateContext(ctx);
    // }
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.exiting(OAuth2StoreImpl.LOG_CLASS,
          "setTokenInfo(securityToken, consumer, serviceName, tokenName, token)");
    }
  }

  public void removeToken(final SecurityToken securityToken, final OAuth2Consumer consumer,
      final String serviceName, final String tokenName) {
    final boolean bIsLogging = OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL);
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.log(OAuth2StoreImpl.LOG_LEVEL,
          "securityToken = {0} , consumer = {1} , serviceName = {2} , tokenName = {3}",
          new Object[] { securityToken, consumer, serviceName, tokenName });
    }
    ++this.accessTokenRemoveCount;
    final OAuth2StoreTokenIndex tokenKey = this.createTokenIndex(securityToken, serviceName,
        tokenName);
    this.tokens.remove(tokenKey);
    // Context c = null;
    // Token t = null;
    // c = this.persister.findContext(serviceName, this.getUser(securityToken));
    // if (c != null) {
    // t = c.getToken();
    // } else {
    // t = null;
    // }
    // if ((c != null) && (c.getId() != null)) {
    // this.persister.deleteContext(c);
    // }
    // if ((t != null) && (t.getId() != null)) {
    // this.persister.deleteToken(t);
    // }
  }

  public int getConsumerKeyLookupCount() {
    return this.consumerKeyLookupCount;
  }

  public int getAccessTokenLookupCount() {
    return this.accessTokenLookupCount;
  }

  public int getAccessTokenAddCount() {
    return this.accessTokenAddCount;
  }

  public int getAccessTokenRemoveCount() {
    return this.accessTokenRemoveCount;
  }

  private OAuth2StoreTokenIndex createTokenIndex(final SecurityToken securityToken,
      final String serviceName, final String tokenName) {
    final boolean bIsLogging = OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL);
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.entering(OAuth2StoreImpl.LOG_CLASS,
          "createTokenIndex(securityToken, serviceName, tokenName)", new Object[] { securityToken,
              serviceName, tokenName });
    }
    final OAuth2StoreTokenIndex index = new OAuth2StoreTokenIndex();
    index.setGadgetUri(securityToken.getAppUrl());
    index.setModuleId(securityToken.getModuleId());
    index.setServiceName(serviceName);
    index.setTokenName(tokenName);
    index.setUserId(securityToken.getViewerId());
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.exiting(OAuth2StoreImpl.LOG_CLASS,
          "createTokenIndex(securityToken, serviceName, tokenName)", index);
    }
    return index;
  }

  private String getUser(final SecurityToken securityToken) {
    final boolean bIsLogging = OAuth2StoreImpl.LOGGER.isLoggable(OAuth2StoreImpl.LOG_LEVEL);
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.entering(OAuth2StoreImpl.LOG_CLASS, "getUser(securityToken)",
          securityToken);
    }
    String ret = null;
    final String viewerId = securityToken.getViewerId();
    if ((viewerId != null) && (viewerId.length() > 0)) {
      ret = viewerId;
    }
    if (bIsLogging) {
      OAuth2StoreImpl.LOGGER.exiting(OAuth2StoreImpl.LOG_CLASS, "getUser(securityToken)", ret);
    }
    return ret;
  }

  // private OAuthAccessor getOAuthAccessor(final Context context) {
  // if (context == null) {
  // return null;
  // }
  //
  // final Client client = context.getClient();
  // final Provider provider = client.getProvider();
  // final OAuthServiceProvider sp = new
  // OAuthServiceProvider(provider.getRequesttokenurl(),
  // provider.getAuthorizeurl(), provider.getAccesstokenurl());
  //
  // final OAuthConsumer consumer = new OAuthConsumer(client.getCallbackurl(),
  // client.getToken().getToken(), client
  // .getToken().getSecret(), sp);
  // // use the signature method specified in provider
  // consumer.setProperty(OAuth.OAUTH_SIGNATURE_METHOD,
  // provider.getSignmethod());
  // final OAuthAccessor accessor = new OAuthAccessor(consumer);
  //
  // final Token token = context.getToken();
  // if (token != null) {
  // if (context.getAuthorized() != 1) {
  // accessor.requestToken = token.getToken();
  // } else {
  // accessor.accessToken = token.getToken();
  // }
  // accessor.tokenSecret = token.getSecret();
  // }
  //
  // return accessor;
  // }
}
