package org.springframework.security.oauth.examples.sparklr;

/**
 * Photo information.
 *
 * @author Ryan Heaton
 */
public class PhotoInfo {

  private String id;
  private String resourceURL;
  private String name;
  private String userId;

  /**
   * Id of the photo.
   *
   * @return Id of the photo.
   */
  public String getId() {
    return id;
  }

  /**
   * Id of the photo.
   *
   * @param id Id of the photo.
   */
  public void setId(String id) {
    this.id = id;
  }

  /**
   * The resource URL.
   *
   * @return The resource URL.
   */
  public String getResourceURL() {
    return resourceURL;
  }

  /**
   * The resource URL.
   *
   * @param resourceURL The resource URL
   */
  public void setResourceURL(String resourceURL) {
    this.resourceURL = resourceURL;
  }

  /**
   * Name of the photo.
   *
   * @return Name of the photo.
   */
  public String getName() {
    return name;
  }

  /**
   * Name of the photo.
   *
   * @param name Name of the photo.
   */
  public void setName(String name) {
    this.name = name;
  }

  /**
   * The id of the user to whom the photo belongs.
   *
   * @return The id of the user to whom the photo belongs.
   */
  public String getUserId() {
    return userId;
  }

  /**
   * The id of the user to whom the photo belongs.
   *
   * @param userId The id of the user to whom the photo belongs.
   */
  public void setUserId(String userId) {
    this.userId = userId;
  }
}
