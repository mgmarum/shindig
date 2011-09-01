/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.sample;

import java.util.List;

import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.oauth2.OAuth2FetcherConfig;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;
import org.apache.shindig.gadgets.oauth2.core.Parameter;

import com.google.inject.Inject;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class BasicOAuth2Request implements org.apache.shindig.gadgets.oauth2.OAuth2Request {
  private final OAuth2Store store;
  private final HttpFetcher fetcher;
  private final OAuth2FetcherConfig config;

  @Inject
  public BasicOAuth2Request(final HttpFetcher fetcher, final OAuth2FetcherConfig config) {
    this.store = null;
    this.fetcher = fetcher;
    this.config = config;
  }

  public HttpResponse fetch(final HttpRequest request) {
    throw new RuntimeException("@@@ WHOA THERE!!!! OAuth2Request needs to be implemented");
  }

  public HttpRequest sanitizeAndSign(final HttpRequest arg0, final List<Parameter> arg1,
      final boolean arg2) throws OAuth2RequestException {
    throw new RuntimeException("@@@ WHOA THERE!!!! OAuth2Request needs to be implemented");
  }
}
