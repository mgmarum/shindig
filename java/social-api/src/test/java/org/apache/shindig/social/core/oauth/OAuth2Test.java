package org.apache.shindig.social.core.oauth;

import org.apache.http.util.ByteArrayBuffer;
import org.apache.shindig.common.testing.FakeHttpServletRequest;
import org.apache.shindig.social.core.oauth2.AuthorizationCode;
import org.apache.shindig.social.core.oauth2.OAuth2ClientRegistration;
import org.apache.shindig.social.core.oauth2.OAuth2Token;
import org.apache.shindig.social.core.oauth2.OAuth2Token.TokenType;
import org.apache.shindig.social.dataservice.integration.AbstractLargeRestfulTests;
import org.apache.shindig.social.dataservice.integration.TestUtils;
import org.apache.shindig.social.opensocial.oauth.OAuth2DataStore;
import org.apache.shindig.social.sample.oauth.SampleOAuth2Servlet;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;

public class OAuth2Test extends AbstractLargeRestfulTests {

  protected static final String SIMPLE_ACCESS_TOKEN = "TEST_TOKEN";
  protected static final String PUBLIC_CLIENT_ID = "client";
  protected static final String PUBLIC_AUTH_CODE = "SplxlOBeZQQYbYS6WxSbIA";
  
  protected SampleOAuth2Servlet servlet = null;
  
  @Before
  public void oauth2SetUp() throws Exception{
    OAuth2DataStore dataStore = mock(OAuth2DataStore.class);
    servlet = new SampleOAuth2Servlet();
    servlet.setDataStore(dataStore);
    servlet.registerGrantHandlers();
    OAuth2ClientRegistration sclient = new OAuth2ClientRegistration();
    sclient.setClientId(PUBLIC_CLIENT_ID);
    EasyMock.expect(dataStore.lookupClient(PUBLIC_CLIENT_ID)).andReturn(sclient).anyTimes();
    AuthorizationCode code = new AuthorizationCode(PUBLIC_AUTH_CODE, sclient);
    EasyMock.expect(dataStore.retrieveAuthorizationCode(sclient, PUBLIC_AUTH_CODE)).andReturn(code).anyTimes();
    OAuth2Token token = new OAuth2Token(SIMPLE_ACCESS_TOKEN);
    token.setClientReg(sclient);
    token.setType(TokenType.ACCESS);
    EasyMock.expect(dataStore.generateAccessToken(sclient, code)).andReturn(token).anyTimes();
  }
  
  @Test
  public void testGetAccessToken() throws Exception{
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + PUBLIC_CLIENT_ID + "&grant_type=authorization_code&redirect_uri=/redirect&code="+PUBLIC_AUTH_CODE);
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    MockServletOutputStream outputStream = new MockServletOutputStream();
//    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    PrintWriter writer = new PrintWriter(outputStream);
    EasyMock.expect(resp.getWriter()).andReturn(writer);
    EasyMock.expect(resp.getOutputStream()).andReturn(outputStream).anyTimes();
    resp.setCharacterEncoding("UTF-8");
    replay();
    servlet.service(req, resp);
    writer.flush();
    InputStream stream = getClass().getResourceAsStream("SimpleOAuth2AccessToken.json");
    InputStreamReader reader = new InputStreamReader(stream,"UTF-8");
    BufferedReader buff = new BufferedReader(reader);
    StringBuilder sb = new StringBuilder();
    String line;
    while ((line = buff.readLine()) != null) {
      sb.append(line);
    }
    String expected =  sb.toString();
    TestUtils.jsonsEqual(expected, new String(outputStream.getBuffer(),"UTF-8"));
  }
  
  private class MockServletOutputStream extends ServletOutputStream {
    private ByteArrayBuffer buffer = new ByteArrayBuffer(1024);

    @Override
    public void write(int b) {
      buffer.append(b);
    }

    public byte[] getBuffer() {
      return buffer.toByteArray();
    }
  }

}
