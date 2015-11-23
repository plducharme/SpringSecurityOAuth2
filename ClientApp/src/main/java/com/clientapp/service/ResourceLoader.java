package com.clientapp.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.stereotype.Component;

@Component
public class ResourceLoader {

	@Autowired
	private OAuth2RestOperations myRestTemplate;

	@SuppressWarnings("unchecked")
	public Object loadResource(String url, Class responseType, Object... urlVariables) {
		return myRestTemplate.getForObject(url, responseType, urlVariables);
	}

}
