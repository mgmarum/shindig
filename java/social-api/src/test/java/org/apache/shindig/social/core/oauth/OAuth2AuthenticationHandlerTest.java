package org.apache.shindig.social.core.oauth;

import org.apache.shindig.auth.AuthenticationHandler.InvalidAuthenticationException;
import org.apache.shindig.common.EasyMockTestCase;
import org.apache.shindig.common.testing.FakeHttpServletRequest;
import org.apache.shindig.social.core.oauth2.OAuth2AuthenticationHandler;
import org.apache.shindig.social.core.oauth2.OAuth2Exception;
import org.apache.shindig.social.core.oauth2.OAuth2Service;
import org.apache.shindig.social.core.oauth2.OAuth2Token;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

public class OAuth2AuthenticationHandlerTest extends EasyMockTestCase {
  
  OAuth2Service mockStore = mock(OAuth2Service.class);
  private final String ACCESS_TOKEN = "123456789";
  private final String CLIENT_ID = "client";
  protected OAuth2AuthenticationHandler handler = null;
  
  @Before
  public void setUp(){
    handler = new OAuth2AuthenticationHandler(mockStore);
  }
  
  private void expectAccessToken() {
      try {
        OAuth2Token token = new OAuth2Token(ACCESS_TOKEN);
        EasyMock.expect(mockStore.retrieveAccessToken(EasyMock.eq(CLIENT_ID),EasyMock.eq(ACCESS_TOKEN))).andReturn(token);
      } catch (OAuth2Exception e) {
        e.printStackTrace();
      }
  }
  
  @Test
  public void testValidAccessToken() throws InvalidAuthenticationException{
    expectAccessToken();
    replay();
    handler.getSecurityTokenFromRequest(new FakeHttpServletRequest("http://localhost:8080/oauth2", "/authorize", "client_id=client&access_token="+ACCESS_TOKEN));
    //Should not throw exception
  }
  
  @Test
  public void testInvalidAccessToken(){
    expectAccessToken();
    replay();
    try {
      handler.getSecurityTokenFromRequest(new FakeHttpServletRequest("http://localhost:8080/oauth2", "/authorize", "access_token=BADTOKEN&client_id=client"));
    }catch(InvalidAuthenticationException ex){
      return;
    }
    fail("Handler allowed invalid token without throwing exception");
    //Should not throw exception
  }

}
