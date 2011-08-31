package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.oauth.OAuthFetcherConfig;
import org.apache.shindig.gadgets.oauth2.OAuth2Request;
import org.apache.shindig.gadgets.oauth2.BasicOAuth2Request;

import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Provider;

public class OAuth2Module extends AbstractModule {

	@Override
	protected void configure() {
	    bind(OAuth2Request.class).toProvider(OAuth2RequestProvider.class);
		
	}
	
	  public static class OAuth2RequestProvider implements Provider<OAuth2Request> {
		    private final HttpFetcher fetcher;
		    private final OAuthFetcherConfig config;

		    @Inject
		    public OAuth2RequestProvider(HttpFetcher fetcher, OAuthFetcherConfig config) {
		      this.fetcher = fetcher;
		      this.config = config;
		    }

		    public OAuth2Request get() {
		      return new BasicOAuth2Request(config, fetcher);
		    }
		  }
}
