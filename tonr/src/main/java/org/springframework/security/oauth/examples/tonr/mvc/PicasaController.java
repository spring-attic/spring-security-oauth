package org.springframework.security.oauth.examples.tonr.mvc;

import org.springframework.security.oauth.examples.tonr.GoogleService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@Controller
public class PicasaController {

	private GoogleService googleService;

	@RequestMapping("/google/picasa")
	public String photos(Model model) throws Exception {
		model.addAttribute("photoUrls", googleService.getLastTenPicasaPictureURLs());
		return "picasa";
	}

	public void setGoogleService(GoogleService googleService) {
		this.googleService = googleService;
	}
}
