package com.cgi.security.oauth2;

import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

public class ExtendedBaseOAuth2ProtectedResourceDetails extends
		AuthorizationCodeResourceDetails {

	@Override
	public boolean isClientOnly() {
		return true;
	}




	
	
	

}
