package com.resource.controller;

import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class BaseController {
	private final static org.slf4j.Logger logger = LoggerFactory.getLogger(BaseController.class);

	// localhost:8080/ResourceServer/
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String helloworld(ModelMap model) {
		// aller a index.jsp (hello world)
		return "index";

	}

	// localhost:8080/ResourceServer/resource
	@RequestMapping(value = "/resource", method = RequestMethod.GET)
	@ResponseBody
	public String publicResource() {
		return theResource();
	}

	// localhost:8080/ResourceServer/basicauth/resource myuser:myuser
	@RequestMapping(value = "/basicauth/resource", method = RequestMethod.GET)
	@ResponseBody
	public String protectedResource() {
		return theResource();
	}

	// localhost:8080/ResourceServer/oauth/resource?access_token="fredo"
	@RequestMapping(value = "/oauth/resource", method = RequestMethod.GET)
	@ResponseBody
	public String tokenResource() {
		return theResource();
	}

	private String theResource() {
		StringBuilder cv = new StringBuilder();
		cv.append("Ceci est une ressource, demandee par '").append(getUserName()).append(" '.");
		return cv.toString();
	}

	private String getUserName() {
		String username;

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			username = ">>pas authentifie<<";
		} else {
			Object principal = authentication.getPrincipal();
			if (principal instanceof UserDetails) {
				username = ((UserDetails) principal).getUsername();
			} else {
				username = principal.toString();
			}
		}
		return username;
	}

}
