/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */

package org.apache.shindig.gadgets.oauth2;

import java.util.List;

import org.apache.shindig.common.Nullable;
import org.apache.shindig.common.servlet.Authority;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Cache;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Encrypter;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2PersistenceException;
import org.apache.shindig.gadgets.oauth2.persistence.OAuth2Persister;
import org.apache.shindig.gadgets.oauth2.persistence.sample.JSONOAuth2Persister;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import com.google.inject.name.Named;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2Module extends AbstractModule {
  private static final String OAUTH2_REDIRECT_URI = "shindig.signing.oauth2.global-redirect-uri";
  private static final String OAUTH2_IMPORT = "shindig.oauth2.import";
  private static final String OAUTH2_IMPORT_CLEAN = "shindig.oauth2.import.clean";

  @Override
  protected void configure() {
    // Used for persistent storage of OAuth2 access tokens.
    this.bind(OAuth2Store.class).toProvider(OAuth2StoreProvider.class);
    this.bind(OAuth2Request.class).toProvider(OAuth2RequestProvider.class);
  }

  public static class OAuth2RequestProvider implements Provider<OAuth2Request> {
    private final HttpFetcher fetcher;
    private final OAuth2FetcherConfig config;
    private final List<OAuth2TokenTypeHandler> tokenTypeHandlers;
    private final List<OAuth2GrantTypeHandler> grantTypeHandlers;
    private final List<OAuth2ClientAuthenticationHandler> authenticationHandlers;

    @Inject
    public OAuth2RequestProvider(final HttpFetcher fetcher, final OAuth2FetcherConfig config,
        final List<OAuth2TokenTypeHandler> tokenTypeHandlers,
        final List<OAuth2GrantTypeHandler> grantTypeHandlers,
        final List<OAuth2ClientAuthenticationHandler> authenticationHandlers) {
      this.fetcher = fetcher;
      this.config = config;
      this.tokenTypeHandlers = tokenTypeHandlers;
      this.grantTypeHandlers = grantTypeHandlers;
      this.authenticationHandlers = authenticationHandlers;
    }

    public OAuth2Request get() {
      return new BasicOAuth2Request(this.config, this.fetcher, this.tokenTypeHandlers,
          this.grantTypeHandlers, this.authenticationHandlers);
    }
  }

  @Singleton
  public static class OAuth2StoreProvider implements Provider<OAuth2Store> {

    private final BasicOAuth2Store store;

    @Inject
    public OAuth2StoreProvider(
        @Named(OAuth2Module.OAUTH2_REDIRECT_URI) final String defaultRedirectUri,
        @Named(OAuth2Module.OAUTH2_IMPORT) final boolean importFromConfig,
        @Named(OAuth2Module.OAUTH2_IMPORT_CLEAN) final boolean importClean,
        final Provider<Authority> hostProvider, final OAuth2Cache cache,
        final OAuth2Persister persister, final OAuth2Encrypter encrypter,
        final String globalRedirectUri,
        @Nullable @Named("shindig.contextroot") final String contextRoot,
        final Provider<OAuth2Message> oauth2MessageProvider,
        final List<OAuth2ClientAuthenticationHandler> authenticationHandlers,
        final List<OAuth2GrantTypeHandler> grantTypeHandlers) {

      this.store = new BasicOAuth2Store(cache, persister, oauth2MessageProvider,
          authenticationHandlers, grantTypeHandlers);

      if (importFromConfig) {
        try {
          final OAuth2Persister source = new JSONOAuth2Persister(encrypter, hostProvider,
              globalRedirectUri, contextRoot);
          this.store.runImport(source, persister, importClean);
        } catch (final OAuth2PersistenceException e) {
          e.printStackTrace();
        }
      }

      try {
        this.store.init();
      } catch (final GadgetException e) {
        e.printStackTrace();
      }
    }

    public OAuth2Store get() {
      return this.store;
    }
  }
}
