/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */

package org.apache.shindig.gadgets.oauth2.sample;

import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.shindig.common.crypto.BasicBlobCrypter;
import org.apache.shindig.common.crypto.BlobCrypter;
import org.apache.shindig.common.crypto.Crypto;
import org.apache.shindig.common.logging.i18n.MessageKeys;
import org.apache.shindig.common.servlet.Authority;
import org.apache.shindig.common.util.ResourceLoader;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.oauth2.OAuth2FetcherConfig;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import com.google.inject.name.Named;
import com.google.inject.name.Names;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2Module extends AbstractModule {
  private static final String LOG_CLASS = OAuth2Module.class.getName();
  private static final Level LOG_LEVEL = Level.FINER;
  private static final Logger LOGGER = Logger.getLogger(OAuth2Module.LOG_CLASS);

  private static final String OAUTH_CONFIG = "config/oauth.json";
  private static final String OAUTH_SIGNING_KEY_FILE = "shindig.signing.key-file";
  private static final String OAUTH_SIGNING_KEY_NAME = "shindig.signing.key-name";
  private static final String OAUTH_CALLBACK_URL = "shindig.signing.global-callback-url";

  @Override
  protected void configure() {
    // Used for persistent storage of OAuth2 access tokens.
    this.bind(OAuth2Store.class).toProvider(OAuth2StoreProvider.class);
    this.bind(OAuth2Request.class).toProvider(OAuth2RequestProvider.class);
  }

  @Singleton
  public static class OAuth2CrypterProvider implements Provider<BlobCrypter> {

    private final BlobCrypter crypter;

    @Inject
    public OAuth2CrypterProvider(@Named("shindig.signing.state-key") final String stateCrypterPath)
        throws IOException {
      if (StringUtils.isBlank(stateCrypterPath)) {
        OAuth2Module.LOGGER.info("Using random key for OAuth client-side state encryption");
        if (OAuth2Module.LOGGER.isLoggable(Level.INFO)) {
          OAuth2Module.LOGGER.logp(Level.INFO, OAuth2Module.LOG_CLASS,
              "OAuthCrypterProvider constructor", MessageKeys.USING_RANDOM_KEY);
        }
        this.crypter = new BasicBlobCrypter(
            Crypto.getRandomBytes(BasicBlobCrypter.MASTER_KEY_MIN_LEN));
      } else {
        if (OAuth2Module.LOGGER.isLoggable(Level.INFO)) {
          OAuth2Module.LOGGER.logp(Level.INFO, OAuth2Module.LOG_CLASS,
              "OAuthCrypterProvider constructor", MessageKeys.USING_FILE,
              new Object[] { stateCrypterPath });
        }
        this.crypter = new BasicBlobCrypter(new File(stateCrypterPath));
      }
    }

    public BlobCrypter get() {
      return this.crypter;
    }
  }

  public static class OAuth2RequestProvider implements Provider<OAuth2Request> {
    private final HttpFetcher fetcher;
    private final OAuth2FetcherConfig config;

    @Inject
    public OAuth2RequestProvider(final HttpFetcher fetcher, final OAuth2FetcherConfig config) {
      this.fetcher = fetcher;
      this.config = config;
    }

    public OAuth2Request get() {
      return new OAuth2Request(this.fetcher, this.config);
    }
  }

  @Singleton
  public static class OAuth2StoreProvider implements Provider<OAuth2Store> {

    private final OAuth2Store store;

    @Inject
    public OAuth2StoreProvider(
        @Named(OAuth2Module.OAUTH_SIGNING_KEY_FILE) final String signingKeyFile,
        @Named(OAuth2Module.OAUTH_SIGNING_KEY_NAME) final String signingKeyName,
        @Named(OAuth2Module.OAUTH_CALLBACK_URL) final String defaultCallbackUrl,
        final Provider<Authority> hostProvider) {
      this.store = new OAuth2StoreImpl(null);

      this.loadDefaultKey(signingKeyFile, signingKeyName);
      this.store.setDefaultCallbackUrl(defaultCallbackUrl);
      this.store.setHostProvider(hostProvider);
      this.loadConsumers();
    }

    private void loadDefaultKey(final String signingKeyFile, final String signingKeyName) {
      final OAuth2StoreConsumerKeyAndSecret key = null;
      if (!StringUtils.isBlank(signingKeyFile)) {
        try {
          if (OAuth2Module.LOGGER.isLoggable(Level.INFO)) {
            OAuth2Module.LOGGER.logp(Level.INFO, OAuth2Module.LOG_CLASS, "loadDefaultKey",
                MessageKeys.LOAD_KEY_FILE_FROM, new Object[] { signingKeyFile });
          }
          final String privateKey = IOUtils.toString(ResourceLoader.open(signingKeyFile), "UTF-8");
          // TODO privateKey = OAuth2Store.convertFromOpenSsl(privateKey);
          // TODO key = new OAuth2StoreConsumerKeyAndSecret(null, privateKey,
          // OAuth2KeyType.RSA_PRIVATE,
          // TODO signingKeyName, null);
        } catch (final Throwable t) {
          if (OAuth2Module.LOGGER.isLoggable(Level.WARNING)) {
            OAuth2Module.LOGGER.logp(Level.WARNING, OAuth2Module.LOG_CLASS, "loadDefaultKey",
                MessageKeys.COULD_NOT_LOAD_KEY_FILE, new Object[] { signingKeyFile });
            OAuth2Module.LOGGER
                .logp(Level.WARNING, OAuth2Module.LOG_CLASS, "loadDefaultKey", "", t);
          }
        }
      }
      if (key != null) {
        this.store.setDefaultKey(key);
      } else {
        if (OAuth2Module.LOGGER.isLoggable(Level.WARNING)) {
          OAuth2Module.LOGGER.logp(Level.WARNING, OAuth2Module.LOG_CLASS, "loadDefaultKey",
              MessageKeys.COULD_NOT_LOAD_SIGN_KEY, new Object[] {
                  OAuth2Module.OAUTH_SIGNING_KEY_FILE, OAuth2Module.OAUTH_SIGNING_KEY_NAME });
        }
      }
    }

    private void loadConsumers() {
      try {
        final String oauthConfigString = ResourceLoader.getContent(OAuth2Module.OAUTH_CONFIG);
        this.store.initFromConfigString(oauthConfigString);
      } catch (final Throwable t) {
        if (OAuth2Module.LOGGER.isLoggable(Level.WARNING)) {
          OAuth2Module.LOGGER.logp(Level.WARNING, OAuth2Module.LOG_CLASS, "loadConsumers",
              MessageKeys.FAILED_TO_INIT, new Object[] { OAuth2Module.OAUTH_CONFIG });
          OAuth2Module.LOGGER.log(Level.WARNING, "", t);
        }
      }
    }

    public OAuth2Store get() {
      return this.store;
    }
  }
}
