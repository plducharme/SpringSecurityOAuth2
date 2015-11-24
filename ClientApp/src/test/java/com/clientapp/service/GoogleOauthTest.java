package com.clientapp.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.springframework.security.oauth2.common.AuthenticationScheme.form;
import static org.springframework.security.oauth2.common.AuthenticationScheme.query;

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
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.web.client.HttpClientErrorException;

public class GoogleOauthTest {
	private static final String AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth";
	// private static final String ACCESS_TOKEN_URI =
	// "https://www.googleapis.com/oauth2/v3/token";
	private static final String ACCESS_TOKEN_URI = "https://accounts.google.com/o/oauth2/token";
	private static final String CLIENT_SECRET = "Nrn9a7bKtwuAEmXGJFTB6WgM";
	private static final String CLIENT_ID = "638963840149-d5p79cp00obaumgrderkmjk3dkcecv0p.apps.googleusercontent.com";
	private static final List<String> SCOPES;

	static {
		SCOPES = new ArrayList<String>(6);
		SCOPES.add("openid");
		SCOPES.add("email");
		SCOPES.add("profile");
		// SCOPES.add("write");
		// SCOPES.add("read");
		// SCOPES.add("trust");
	}

	private OAuth2RestOperations oauth2RestTemplate;

	@Test
	public void testRestTemplate() {
		// DefaultAccessTokenRequest accessTokenRequest = new
		// DefaultAccessTokenRequest();
		// accessTokenRequest.setPreservedState("myState");
		// Un code, j'en demande un !
		// accessTokenRequest.setAuthorizationCode("code");
		// accessTokenRequest.setStateKey("myState");

		// OAuth2ProtectedResourceDetails res = usernamePasswordResource();
		OAuth2ProtectedResourceDetails res = authorizationCodeResource();
		// OAuth2ProtectedResourceDetails res = clientCredentialResource();

		oauth2RestTemplate = new OAuth2RestTemplate(res);
		// , new DefaultOAuth2ClientContext(accessTokenRequest));

		HttpHeaders headers = new HttpHeaders();
		// headers.setContentType(MediaType.APPLICATION_JSON);
		headers.setContentType(MediaType.TEXT_PLAIN);
		HttpEntity<String> httpEntity = new HttpEntity<String>("helloWorld", headers);

		try {
			final String loginResponse = oauth2RestTemplate.exchange("https://www.googleapis.com/oauth2/v2/userinfo",
					HttpMethod.POST, httpEntity, String.class).getBody();

			assertNotNull(loginResponse);
		} catch (OAuth2AccessDeniedException e) {
			// ""Code was already redeemed."
			// "Invalid OAuth 2 grant type: CLIENT_CREDENTIALS"
			fail(((HttpClientErrorException) e.getCause()).getResponseBodyAsString());
		}

	}

	// grantType="password"
	private OAuth2ProtectedResourceDetails usernamePasswordResource() {

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

	// grant_type=[authorization_code],
	// redirect_uri=[https://localhost/google_oauth2_login],
	// client_id=[638963840149-d5p79cp00obaumgrderkmjk3dkcecv0p.apps.googleusercontent.com],
	// client_secret=[Nrn9a7bKtwuAEmXGJFTB6WgM]
	private OAuth2ProtectedResourceDetails authorizationCodeResource() {

		AuthorizationCodeResourceDetails googleOAuth2Details = new AuthorizationCodeResourceDetails();

		// googleOAuth2Details.setAuthenticationScheme(header);
		// googleOAuth2Details.setClientAuthenticationScheme(header);
		googleOAuth2Details.setAuthenticationScheme(query);
		googleOAuth2Details.setClientAuthenticationScheme(form);
		googleOAuth2Details.setClientId(CLIENT_ID);
		googleOAuth2Details.setClientSecret(CLIENT_SECRET);
		googleOAuth2Details.setUserAuthorizationUri(AUTHORIZE_URL);
		googleOAuth2Details.setAccessTokenUri(ACCESS_TOKEN_URI);
		googleOAuth2Details.setScope(SCOPES);
		googleOAuth2Details.setUseCurrentUri(false);
		googleOAuth2Details.setPreEstablishedRedirectUri("https://localhost/google_oauth2_login");
		googleOAuth2Details.setTokenName("oauth_token");

		return googleOAuth2Details;
	}

	// grant type: CLIENT_CREDENTIALS
	private OAuth2ProtectedResourceDetails clientCredentialResource() {
		ClientCredentialsResourceDetails resourceDetails = new ClientCredentialsResourceDetails();
		resourceDetails.setClientSecret(CLIENT_SECRET);
		resourceDetails.setClientId(CLIENT_ID);
		resourceDetails.setAccessTokenUri(ACCESS_TOKEN_URI);
		resourceDetails.setScope(SCOPES);
		return resourceDetails;

	}

}
