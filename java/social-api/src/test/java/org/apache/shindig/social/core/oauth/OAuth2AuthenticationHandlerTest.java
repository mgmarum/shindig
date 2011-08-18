package org.apache.shindig.social.core.oauth;

import org.apache.shindig.auth.AuthenticationHandler.InvalidAuthenticationException;
import org.apache.shindig.common.EasyMockTestCase;
import org.apache.shindig.common.testing.FakeHttpServletRequest;
import org.apache.shindig.social.SocialApiTestsGuiceModule;
import org.apache.shindig.social.core.oauth2.OAuth2AuthenticationHandler;
import org.junit.Before;
import org.junit.Test;

import com.google.inject.Guice;

public class OAuth2AuthenticationHandlerTest extends EasyMockTestCase {
  
//  OAuth2Service mockStore = mock(OAuth2Service.class);
  private final String ACCESS_TOKEN = "testClient_accesstoken_1";
  protected OAuth2AuthenticationHandler handler = null;
  
  @Before
  public void setUp(){
    
    handler = Guice.createInjector(new SocialApiTestsGuiceModule()).getInstance(OAuth2AuthenticationHandler.class);
  }
  
  private void expectAccessToken() {

  }
  
  @Test
  public void testValidAccessToken() throws InvalidAuthenticationException{
    expectAccessToken();
    replay();
    handler.getSecurityTokenFromRequest(new FakeHttpServletRequest("http://localhost:8080/oauth2", "/some_protected_uri", "access_token="+ACCESS_TOKEN));
    //Should not throw exception
  }
  
  @Test
  public void testInvalidAccessToken(){
    expectAccessToken();
    replay();
    try {
      handler.getSecurityTokenFromRequest(new FakeHttpServletRequest("http://localhost:8080/oauth2", "/some_protected_uri", "access_token=BADTOKEN"));
    }catch(InvalidAuthenticationException ex){
      return;
    }
    fail("Handler allowed invalid token without throwing exception");
    //Should not throw exception
  }


}
