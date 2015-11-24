package com.clientapp.service;

import static org.junit.Assert.assertNotNull;
import static org.springframework.security.oauth2.common.AuthenticationScheme.form;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;

public class UserServiceTest {
	private static final String AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth";
	private static final String ACCESS_TOKEN_URI = "https://www.googleapis.com/oauth2/v3/token";
	private static final String CLIENT_SECRET = "Nrn9a7bKtwuAEmXGJFTB6WgM";
	private static final String CLIENT_ID = "638963840149-d5p79cp00obaumgrderkmjk3dkcecv0p.apps.googleusercontent.com";
	private static final List<String> SCOPES = new ArrayList<String>(2);

	static {
		// SCOPES.add("openid");
		SCOPES.add("write");
		SCOPES.add("read");
	}

	private OAuth2RestOperations oauth2RestTemplate;

	@Test
	public void testFindUsersStartingWithPrefix() {
		DefaultAccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
		accessTokenRequest.setPreservedState("state");
		accessTokenRequest.setAuthorizationCode("code");
		oauth2RestTemplate = new OAuth2RestTemplate(authorizationCodeResource(),
				new DefaultOAuth2ClientContext(accessTokenRequest));
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.TEXT_PLAIN);
		HttpEntity<String> httpEntity = new HttpEntity<String>("helloWorld", headers);

		final String loginResponse = oauth2RestTemplate
				.exchange("https://www.googleapis.com/oauth2/v2/userinfo", HttpMethod.POST, httpEntity, String.class)
				.getBody();

		assertNotNull(loginResponse);

	}

	private OAuth2ProtectedResourceDetails usernamePasswordresource() {

		ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();

		resource.setAccessTokenUri(ACCESS_TOKEN_URI);
		resource.setClientId(CLIENT_ID);
		resource.setClientSecret(CLIENT_SECRET);
		resource.setGrantType("password");
		resource.setScope(SCOPES);

		resource.setUsername("myUsr");
		resource.setPassword("myPwd");

		return resource;
	}

	public OAuth2ProtectedResourceDetails authorizationCodeResource() {

		AuthorizationCodeResourceDetails googleOAuth2Details = new AuthorizationCodeResourceDetails();

		googleOAuth2Details.setAuthenticationScheme(form);
		googleOAuth2Details.setClientAuthenticationScheme(form);
		googleOAuth2Details.setClientId(CLIENT_ID);
		googleOAuth2Details.setClientSecret(CLIENT_SECRET);
		googleOAuth2Details.setUserAuthorizationUri(AUTHORIZE_URL);
		googleOAuth2Details.setAccessTokenUri(ACCESS_TOKEN_URI);
		googleOAuth2Details.setScope(SCOPES);

		return googleOAuth2Details;
	}

}
