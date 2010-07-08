package org.springframework.security.oauth.examples.sparklr.mvc;

import org.springframework.web.servlet.mvc.AbstractController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.security.oauth.examples.sparklr.PhotoService;
import org.springframework.security.oauth.examples.sparklr.PhotoInfo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Iterator;
import java.io.PrintWriter;

/**
 * Controller for managing the lists of controllers for a person.
 *
 * @author Ryan Heaton
 */
public class PhotosController extends AbstractController {

  private PhotoService photoService;

  protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
    Collection<PhotoInfo> photos = photoService.getPhotosForCurrentUser();
    String uri = request.getRequestURI();
    if (uri.contains("json")) {
      response.setContentType("application/json");
      PrintWriter out = response.getWriter();
      if (request.getParameter("callback") != null) {
        out.print(request.getParameter("callback"));
        out.print("( ");
      }
      out.print("{ \"photos\" : [ ");
      Iterator<PhotoInfo> photosIt = photos.iterator();
      while (photosIt.hasNext()) {
        PhotoInfo photo = photosIt.next();
        out.print(String.format("{ \"id\" : \"%s\" , \"name\" : \"%s\" }", photo.getId(), photo.getName()));
        if (photosIt.hasNext()) {
          out.print(" , ");
        }
      }
      out.print("] }");
      if (request.getParameter("callback") != null) {
        out.print(" )");
      }
    }
    else {
      response.setContentType("application/xml");
      PrintWriter out = response.getWriter();
      out.print("<photos>");
      for (PhotoInfo photo : photos) {
        out.print(String.format("<photo id=\"%s\" name=\"%s\"/>", photo.getId(), photo.getName()));
      }
      out.print("</photos>");
    }
    return null;
  }

  public PhotoService getPhotoService() {
    return photoService;
  }

  public void setPhotoService(PhotoService photoService) {
    this.photoService = photoService;
  }
}
