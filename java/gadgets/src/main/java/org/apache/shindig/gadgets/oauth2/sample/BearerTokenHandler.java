package org.apache.shindig.gadgets.oauth2.sample;

import org.apache.shindig.gadgets.oauth2.OAuth2TokenTypeHandler;

import com.google.inject.Inject;

public class BearerTokenHandler implements OAuth2TokenTypeHandler {

  @Inject
  public BearerTokenHandler() {
    
  }
}
