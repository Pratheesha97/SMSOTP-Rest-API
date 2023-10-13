package org.wso2.identity.oauth.grant.smsotp;

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;


/**
 * This validate the smsotp grant request.
 */
public class SMSOTPGrantValidator extends AbstractValidator<HttpServletRequest> {


    public SMSOTPGrantValidator() {

        // grant type must be in the request parameter
        requiredParams.add(OAuth.OAUTH_GRANT_TYPE);
        // transaction Id must be in the request parameter
        requiredParams.add(SMSOTPGrantConstants.GRANT_PARAM_TRANSACTION_ID);
        // user Id must be in the request parameter
        requiredParams.add(SMSOTPGrantConstants.GRANT_PARAM_USERID);
        // smsotp must be in the request parameter
        requiredParams.add(SMSOTPGrantConstants.GRANT_PARAM_OTP);
    }
}
