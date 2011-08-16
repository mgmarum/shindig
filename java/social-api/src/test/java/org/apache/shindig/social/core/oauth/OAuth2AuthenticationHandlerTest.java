package org.apache.shindig.social.core.oauth;

import org.apache.shindig.auth.AuthenticationHandler.InvalidAuthenticationException;
import org.apache.shindig.common.EasyMockTestCase;
import org.apache.shindig.common.testing.FakeHttpServletRequest;
import org.apache.shindig.social.core.oauth2.OAuth2AuthenticationHandler;
import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2Token;
import org.apache.shindig.social.opensocial.oauth.OAuth2DataStore;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

public class OAuth2AuthenticationHandlerTest extends EasyMockTestCase {
  
  OAuth2DataStore mockStore = mock(OAuth2DataStore.class);
  private final String ACCESS_TOKEN = "123456789";
  protected OAuth2AuthenticationHandler handler = null;
  
  @Before
  public void setUp(){
    handler = new OAuth2AuthenticationHandler(mockStore);
  }
  
  private void expectAccessToken() {
      try {
        OAuth2Token token = new OAuth2Token(ACCESS_TOKEN);
        EasyMock.expect(mockStore.retrieveToken(EasyMock.eq(ACCESS_TOKEN))).andReturn(token);
      } catch (OAuth2Exception e) {
        e.printStackTrace();
      }
  }
  
  @Test
  public void testValidAccessToken() throws InvalidAuthenticationException{
    expectAccessToken();
    replay();
    handler.getSecurityTokenFromRequest(new FakeHttpServletRequest("http://localhost:8080/oauth2", "/authorize", "access_token="+ACCESS_TOKEN));
    //Should not throw exception
  }
  
  @Test
  public void testInvalidAccessToken(){
    expectAccessToken();
    replay();
    try {
      handler.getSecurityTokenFromRequest(new FakeHttpServletRequest("http://localhost:8080/oauth2", "/authorize", "access_token=BADTOKEN"));
    }catch(InvalidAuthenticationException ex){
      return;
    }
    fail("Handler allowed invalid token without throwing exception");
    //Should not throw exception
  }

}
