package com.clientapp.service;

import java.util.ArrayList;
import java.util.List;

import org.codehaus.jackson.JsonProcessingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

public class UserService {
	@Autowired
	private OAuth2RestOperations oauth2RestTemplate;

	@RequestMapping(method = RequestMethod.GET)
	public @ResponseBody List<String> findUsersStartingWithPrefix(@RequestParam("term") String usernamePrefix)
			throws JsonProcessingException {
		List<String> list = new ArrayList<String>(2);
		list.add("user@email.com");
		list.add("user2@email.com");

		GoogleProfile profile = getGoogleProfile();
		list.add(profile.getEmail());

		return list;
	}

	private GoogleProfile getGoogleProfile() {
		String url = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
				+ oauth2RestTemplate.getAccessToken();
		ResponseEntity<GoogleProfile> forEntity = oauth2RestTemplate.getForEntity(url, GoogleProfile.class);
		return forEntity.getBody();
	}
}
