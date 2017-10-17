/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */


package org.springframework.security.oauth2.provider.endpoint;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.device.DeviceAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.device.InMemoryDeviceAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.support.RequestContext;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 * Endpoint for device flow: device authorize and user grant
 * https://tools.ietf.org/html/draft-ietf-oauth-device-flow-06
 *
 * @author Bin Wang
 */

@FrameworkEndpoint
public class DeviceAuthorizationEndpoint extends AbstractEndpoint {

    private DeviceAuthorizationCodeServices deviceAuthorizationCodeServices=new InMemoryDeviceAuthorizationCodeServices();
    private OAuth2RequestValidator oauth2RequestValidator = new DefaultOAuth2RequestValidator();
    private static int DEFAULT_INTERVAL=2;

    private static String PREFIX="device_";

    @RequestMapping(value = "/oauth/device_authorize",method = RequestMethod.POST)
    @ResponseBody
    public Map<String,?> deviceAuthorize(@RequestParam Map<String, String> parameters, Principal principal, HttpServletRequest request){

        AuthorizationRequest authorizationRequest = getOAuth2RequestFactory().createAuthorizationRequest(parameters);
        if (authorizationRequest.getClientId() == null) {
            throw new InvalidClientException("A client id must be provided");
        }

        if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
            throw new InsufficientAuthenticationException(
                    "User must be authenticated with Spring Security before authorization can be completed.");
        }

        ClientDetails client = getClientDetailsService().loadClientByClientId(authorizationRequest.getClientId());
        // We intentionally only validate the parameters requested by the client (ignoring any data that may have
        // been added to the request by the manager).
        oauth2RequestValidator.validateScope(authorizationRequest, client);

        String[] codes=deviceAuthorizationCodeServices.createAuthorizationCodes(authorizationRequest.createOAuth2Request());
        Map response=new HashMap();
        response.put(OAuth2Utils.DEVICE_CODE,codes[0]);
        response.put(OAuth2Utils.USER_CODE,codes[1]);
        String verifyurl=null;
        try {
          verifyurl = client.getAdditionalInformation().get(PREFIX+OAuth2Utils.VERIFICATION_URI).toString();

        }catch (Exception ex){}
        if(StringUtils.isEmpty(verifyurl)) {
            StringBuffer url = request.getRequestURL();
            verifyurl= url.substring(0,url.lastIndexOf("/"))+"/user_verify";
        }
        response.put(OAuth2Utils.VERIFICATION_URI,verifyurl);
        Integer interval=null;
        try{
            interval=Integer.parseInt(client.getAdditionalInformation().get(PREFIX+OAuth2Utils.INTERVAL).toString());

        }catch (Exception ex) {

        }

        response.put(OAuth2Utils.INTERVAL,interval!=null?interval:DEFAULT_INTERVAL);

        response.put(OAuth2AccessToken.EXPIRES_IN,deviceAuthorizationCodeServices.getExpiresIn());

        return response;
    }


    public void setDeviceAuthorizationCodeServices(DeviceAuthorizationCodeServices deviceAuthorizationCodeServices) {
        this.deviceAuthorizationCodeServices = deviceAuthorizationCodeServices;
    }

    public void setOauth2RequestValidator(OAuth2RequestValidator oauth2RequestValidator) {
        this.oauth2RequestValidator = oauth2RequestValidator;
    }
}
