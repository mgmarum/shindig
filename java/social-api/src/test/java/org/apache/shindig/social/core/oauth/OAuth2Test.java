package org.apache.shindig.social.core.oauth;

import org.apache.http.util.ByteArrayBuffer;
import org.apache.shindig.common.testing.FakeHttpServletRequest;
import org.apache.shindig.social.core.oauth2.OAuth2Client;
import org.apache.shindig.social.core.oauth2.OAuth2Client.ClientType;
import org.apache.shindig.social.core.oauth2.AuthorizationCodeGrant;
import org.apache.shindig.social.core.oauth2.OAuth2Code;
import org.apache.shindig.social.core.oauth2.OAuth2NormalizedRequest;
import org.apache.shindig.social.core.oauth2.OAuth2Service;
import org.apache.shindig.social.core.oauth2.OAuth2Servlet;
import org.apache.shindig.social.core.oauth2.OAuth2Token;
import org.apache.shindig.social.core.oauth2.OAuth2Token.TokenType;
import org.apache.shindig.social.dataservice.integration.AbstractLargeRestfulTests;
import org.apache.shindig.social.dataservice.integration.TestUtils;
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
  
  protected OAuth2Servlet servlet = null;
  protected OAuth2Service dataStore = null;
  protected final OAuth2Client PUBLIC_CLIENT = new OAuth2Client();
  
  @Before
  public void oauth2SetUp() throws Exception{
    dataStore = mock(OAuth2Service.class);
    servlet = new OAuth2Servlet();
    servlet.setOAuth2Service(dataStore);
    PUBLIC_CLIENT.setId(PUBLIC_CLIENT_ID);
    PUBLIC_CLIENT.setType(ClientType.PUBLIC);
    EasyMock.expect(dataStore.getClientById(PUBLIC_CLIENT_ID)).andReturn(PUBLIC_CLIENT).anyTimes();
    OAuth2Code code = new OAuth2Code(PUBLIC_AUTH_CODE);
    code.setClient(PUBLIC_CLIENT);
    EasyMock.expect(dataStore.retrieveAuthCode(PUBLIC_CLIENT_ID, PUBLIC_AUTH_CODE)).andReturn(code).anyTimes();
  }
  
  @Test
  public void testGetAccessToken() throws Exception{
    OAuth2Token token = new OAuth2Token(SIMPLE_ACCESS_TOKEN);
    token.setClient(PUBLIC_CLIENT);
    token.setType(TokenType.ACCESS);
    FakeHttpServletRequest req = 
      new FakeHttpServletRequest("http://localhost:8080","/oauth2",
          "client_id=" + PUBLIC_CLIENT_ID + "&grant_type=authorization_code&redirect_uri=/redirect&code="+PUBLIC_AUTH_CODE);
    req.setMethod("GET");
    req.setServletPath("/oauth2");
    req.setPathInfo("/access_token");
    EasyMock.expect(dataStore.generateAccessToken(EasyMock.eq(new OAuth2NormalizedRequest(req)))).andReturn(token).anyTimes();
    EasyMock.expect(dataStore.getAuthorizationGrantHandler("authorization_code")).andReturn(new AuthorizationCodeGrant(dataStore)).anyTimes();
    HttpServletResponse resp = mock(HttpServletResponse.class);
    MockServletOutputStream outputStream = new MockServletOutputStream();
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
