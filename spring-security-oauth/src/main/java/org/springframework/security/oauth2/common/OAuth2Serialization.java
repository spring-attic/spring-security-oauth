package org.springframework.security.oauth2.common;

/**
 * Basic OAuth 2 serialization.
 *
 * @author Ryan Heaton
 */
public class OAuth2Serialization {

  private String mediaType;
  private String serializedForm;

  public OAuth2Serialization() {
  }

  public OAuth2Serialization(String mediaType, String serializedForm) {
    this.mediaType = mediaType;
    this.serializedForm = serializedForm;
  }

  public String getMediaType() {
    return mediaType;
  }

  public void setMediaType(String mediaType) {
    this.mediaType = mediaType;
  }

  public String getSerializedForm() {
    return serializedForm;
  }

  public void setSerializedForm(String serializedForm) {
    this.serializedForm = serializedForm;
  }

  @Override
  public String toString() {
    return getSerializedForm();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    OAuth2Serialization that = (OAuth2Serialization) o;

    if (mediaType != null ? !mediaType.equals(that.mediaType) : that.mediaType != null) {
      return false;
    }
    if (serializedForm != null ? !serializedForm.equals(that.serializedForm) : that.serializedForm != null) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    int result = mediaType != null ? mediaType.hashCode() : 0;
    result = 31 * result + (serializedForm != null ? serializedForm.hashCode() : 0);
    return result;
  }
}
