package com.cgi.security.oauth2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

public class DefaultLocalAuthenticationFilter extends AbstractAuthenticationProcessingFilter{

	private OAuth2RestOperations oauth2RestTemplate;
	
	private static final String AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth";
	// private static final String ACCESS_TOKEN_URI =
	// "https://www.googleapis.com/oauth2/v3/token";
	private static final String ACCESS_TOKEN_URI = "https://accounts.google.com/o/oauth2/token";
	private static final String CLIENT_SECRET = "Nrn9a7bKtwuAEmXGJFTB6WgM";
	private static final String CLIENT_ID = "638963840149-d5p79cp00obaumgrderkmjk3dkcecv0p.apps.googleusercontent.com";
	private static final String REDIRECT_URI = "http://localhost:8080";
	private static final List<String> SCOPES;

	static {
		SCOPES = new ArrayList<String>();
		SCOPES.add("openid");
		SCOPES.add("email");
		SCOPES.add("profile");
		// SCOPES.add("write");
		// SCOPES.add("read");
		// SCOPES.add("trust");
	}
	
	
	protected DefaultLocalAuthenticationFilter() {
		super("/DefaultLocalAuthenticationFilter");
	}


	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req; 
		if (request.getParameter("code") != null) {
			AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProvider = new AuthorizationCodeAccessTokenProvider();
			
			

			
			//oauth2RestTemplate = new OAuth2RestTemplate(res);
			DefaultAccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
			accessTokenRequest.setAuthorizationCode(request.getParameter("code"));
			DefaultOAuth2ClientContext defaultOAuth2ClientContext = new DefaultOAuth2ClientContext(accessTokenRequest);
			
			AuthorizationCodeResourceDetails googleOAuth2Details = new AuthorizationCodeResourceDetails();

			// googleOAuth2Details.setAuthenticationScheme(header);
			// googleOAuth2Details.setClientAuthenticationScheme(header);
			googleOAuth2Details.setAuthenticationScheme(AuthenticationScheme.query);
			googleOAuth2Details.setClientAuthenticationScheme(AuthenticationScheme.form);
			googleOAuth2Details.setClientId(CLIENT_ID);
			googleOAuth2Details.setClientSecret(CLIENT_SECRET);
			googleOAuth2Details.setUserAuthorizationUri(AUTHORIZE_URL);
			googleOAuth2Details.setAccessTokenUri(ACCESS_TOKEN_URI);
			googleOAuth2Details.setScope(SCOPES);
			googleOAuth2Details.setUseCurrentUri(false);
			googleOAuth2Details.setPreEstablishedRedirectUri(REDIRECT_URI);
			googleOAuth2Details.setTokenName("oauth_token");
			googleOAuth2Details.setGrantType("authorization_code");

			
			
			OAuth2AccessToken accessToken = authorizationCodeAccessTokenProvider.obtainAccessToken(googleOAuth2Details, accessTokenRequest);
			
			defaultOAuth2ClientContext.setAccessToken(accessToken);
			request.getSession(true).setAttribute("SuperToken", accessToken);
			
//			oauth2RestTemplate = new OAuth2RestTemplate(googleOAuth2Details, defaultOAuth2ClientContext);
//		
//			
//			
//			HttpHeaders headers = new HttpHeaders();
//			headers.setContentType(MediaType.APPLICATION_JSON);
//			//headers.setContentType(MediaType.TEXT_PLAIN);
//			
//			HttpEntity<String> httpEntity = new HttpEntity<String>("helloWorld", headers );	
//			 //SecurityContextHolder.getContext().setAuthentication(attemptAuthentication((HttpServletRequest) req, (HttpServletResponse) res));
//			final String loginResponse = oauth2RestTemplate.exchange("https://www.googleapis.com/o/oauth2",
//					HttpMethod.POST, httpEntity, String.class).getBody();
		} else {
	         HttpServletResponse resp = (HttpServletResponse) res;
	         resp.setStatus(resp.SC_MOVED_PERMANENTLY);
	         resp.setHeader("Location", "https://accounts.google.com/o/oauth2/auth?client_id=638963840149-d5p79cp00obaumgrderkmjk3dkcecv0p.apps.googleusercontent.com&redirect_uri=http://localhost:8080&response_type=code&scope=profile+email+openid");
	         
		}
		
		 
		 chain.doFilter(req, res);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		logger.debug("DefaultLocalAuthenticationFilter::attemptAuthentication");
		Authentication authentication = new TestingAuthenticationToken("local", "local");
		authentication.setAuthenticated(true);
		return getAuthenticationManager().authenticate(authentication);
	}
	
	
	
	
	
}
