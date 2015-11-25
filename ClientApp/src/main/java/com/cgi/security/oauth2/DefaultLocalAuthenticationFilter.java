package com.cgi.security.oauth2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

public class DefaultLocalAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private String tokenAttribute;
	private String authorizeUrl;
	private String accessTokenUri;
	private String clientSecret;
	private String clientId;
	private String redirectUri;
	private String scope;
	private static final List<String> SCOPES;

	static {
		SCOPES = new ArrayList<String>(6);
		SCOPES.add("openid");
		SCOPES.add("email");
		SCOPES.add("profile");
	}

	protected DefaultLocalAuthenticationFilter() {
		super("/DefaultLocalAuthenticationFilter");
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;

		if (request.getSession() != null && request.getSession().getAttribute(tokenAttribute) != null) {

			chain.doFilter(req, res);
			return;
		}

		String codeParameter = request.getParameter("code");
		if (codeParameter == null) {
			HttpServletResponse resp = (HttpServletResponse) res;
			resp.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
			resp.setHeader("Location", authorizeUrl + "?client_id=" + clientId + "&redirect_uri=" + redirectUri
					+ "&response_type=" + "code&scope=" + scope);

		} else {
			final DefaultAccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
			accessTokenRequest.setAuthorizationCode(codeParameter);

			filterWithCode(request, accessTokenRequest);
		}

		chain.doFilter(req, res);
	}

	private void filterWithCode(HttpServletRequest request, final DefaultAccessTokenRequest accessTokenRequest) {
		final AuthorizationCodeResourceDetails googleOAuth2Details = new AuthorizationCodeResourceDetails();

		googleOAuth2Details.setAuthenticationScheme(AuthenticationScheme.query);
		googleOAuth2Details.setClientAuthenticationScheme(AuthenticationScheme.form);
		googleOAuth2Details.setClientId(clientId);
		googleOAuth2Details.setClientSecret(clientSecret);
		googleOAuth2Details.setUserAuthorizationUri(authorizeUrl);
		googleOAuth2Details.setAccessTokenUri(accessTokenUri);
		googleOAuth2Details.setScope(SCOPES);
		googleOAuth2Details.setUseCurrentUri(false);
		googleOAuth2Details.setPreEstablishedRedirectUri(redirectUri);
		googleOAuth2Details.setTokenName("oauth_token");
		googleOAuth2Details.setGrantType("authorization_code");

		final MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
		final List<HttpMessageConverter<?>> converters = new ArrayList<HttpMessageConverter<?>>();
		converters.add(converter);

		final AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProvider = new AuthorizationCodeAccessTokenProvider();
		authorizationCodeAccessTokenProvider.setMessageConverters(converters);
		final OAuth2AccessToken accessToken = authorizationCodeAccessTokenProvider
				.obtainAccessToken(googleOAuth2Details, accessTokenRequest);

		final DefaultOAuth2ClientContext defaultOAuth2ClientContext = new DefaultOAuth2ClientContext(
				accessTokenRequest);
		defaultOAuth2ClientContext.setAccessToken(accessToken);

		request.getSession(true).setAttribute(tokenAttribute, accessToken);

		final Authentication authentication = new TestingAuthenticationToken("internal_system_user",
				"internal_null_credentials", "ROLE_USER");
		authentication.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(authentication);
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
