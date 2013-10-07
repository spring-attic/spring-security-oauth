package org.springframework.security.oauth.examples.tonr.mvc;

import java.awt.image.BufferedImage;
import java.io.InputStream;
import java.util.Iterator;

import javax.imageio.ImageIO;
import javax.imageio.ImageReadParam;
import javax.imageio.ImageReader;
import javax.imageio.stream.MemoryCacheImageInputStream;
import javax.servlet.UnavailableException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@Controller
public class SparklrRedirectController {

	private SparklrService sparklrService;

	@RequestMapping("/sparklr/redirect")
	public String photos(Model model) throws Exception {
		model.addAttribute("photoIds", sparklrService.getSparklrPhotoIds());
		model.addAttribute("path", "redirect");
		return "sparklr";
	}

	@RequestMapping("/sparklr/trigger")
	public String trigger(Model model) throws Exception {
		return photos(model);
	}

	@RequestMapping("/sparklr/redirect/{id}")
	public ResponseEntity<BufferedImage> photo(@PathVariable String id) throws Exception {
		InputStream photo = sparklrService.loadSparklrPhoto(id);
		if (photo == null) {
			throw new UnavailableException("The requested photo does not exist");
		}
		BufferedImage body;
		MediaType contentType = MediaType.IMAGE_JPEG;
		Iterator<ImageReader> imageReaders = ImageIO.getImageReadersByMIMEType(contentType.toString());
		if (imageReaders.hasNext()) {
			ImageReader imageReader = imageReaders.next();
			ImageReadParam irp = imageReader.getDefaultReadParam();
			imageReader.setInput(new MemoryCacheImageInputStream(photo), true);
			body = imageReader.read(0, irp);
		} else {
			throw new HttpMessageNotReadableException("Could not find javax.imageio.ImageReader for Content-Type ["
					+ contentType + "]");
		}
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.IMAGE_JPEG);
		return new ResponseEntity<BufferedImage>(body, headers, HttpStatus.OK);
	}

	public void setSparklrService(SparklrService sparklrService) {
		this.sparklrService = sparklrService;
	}

}
