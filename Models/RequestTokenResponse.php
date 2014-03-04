<?php
/**
 *DTO:
 *Holds data relevant to the Request Token
 */
class RequestTokenResponse
{
    public $requestToken;
    
    public $authorizeUrl;
    
    public $callbackConfirmed;
    
    public $oauthexpiresIn;
    
    public $oauthSecret;
    
    public $redirectURL;
}
