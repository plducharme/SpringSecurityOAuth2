package com.charter.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class OAuth2Controller {
	private static final String ACCESS_TOKEN_URI = "https://accounts.google.com/o/oauth2/token";
	private static final String AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth";
	// PLD's
	// private static final String CLIENT_ID = "638963840149-d5p79cp00obaumgrderkmjk3dkcecv0p.apps.googleusercontent.com";
	// private static final String CLIENT_SECRET = "Nrn9a7bKtwuAEmXGJFTB6WgM";
	// Fred's
	private static final String CLIENT_ID = "366227280997-3ujnhtsiobd77357gs8e521fccr0ldqi.apps.googleusercontent.com";
	private static final String CLIENT_SECRET = "0P__v2rn0cCaS5H97zCfVsNr";
	// redirect_uri_mismatch
	private static final String REDIRECT_URI = "http://localhost:8080/OAuth2App/auth";
	private static final String SCOPES = "profile";

	@RequestMapping(value = "/sa", method = RequestMethod.GET)
	public ModelAndView oAuthController(HttpServletRequest req, HttpServletResponse response)
			throws OAuthSystemException, IOException {

		OAuthClientRequest request = null;

		request = OAuthClientRequest.authorizationLocation(AUTHORIZE_URL).setResponseType("code").setState("1")
				.setClientId(CLIENT_ID).setRedirectURI(REDIRECT_URI).setScope(SCOPES).buildQueryMessage();

		System.out.println("Url de redirection: " + request.getLocationUri());

		return new ModelAndView("redirect:" + request.getLocationUri());
	}

	@RequestMapping(value = "/auth", method = RequestMethod.GET)
	public ModelAndView authCallbackController(HttpServletRequest request, HttpServletResponse response)
			throws IOException, OAuthSystemException, OAuthProblemException {

		OAuthAuthzResponse oar = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
		String stateResponse = oar.getState();

		if (stateResponse.equals("")) {
			return new ModelAndView("posIndex", "message", "Unsuccessful");
		}

		OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
		OAuthAccessTokenResponse oAuthResponse = getAccessToken(oar, oAuthClient);

		System.out.println("Access token: '" + oAuthResponse.getAccessToken() + "'");

		return new ModelAndView("posIndex", "message", "successful");
	}

	private OAuthAccessTokenResponse getAccessToken(OAuthAuthzResponse oar, OAuthClient oAuthClient)
			throws OAuthSystemException, OAuthProblemException {

		String code = oar.getCode();

		OAuthClientRequest request = OAuthClientRequest.tokenLocation(ACCESS_TOKEN_URI)
				.setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(CLIENT_ID).setClientSecret(CLIENT_SECRET)
				.setCode(code).setRedirectURI(REDIRECT_URI).buildBodyMessage();

		return oAuthClient.accessToken(request);
	}
}
