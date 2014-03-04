<?php
/**
 *DTO:
 *Holds data relevant to the Access Token and Checkout Resources
 */
class AccessTokenResponse
{
	public $requestToken;
    
	public $verifier;
    
	public $checkoutResourceUrl;
    
	public $accessToken;
    
	public $paymentShippingResource;
     
	public $oauthSecret;
    
	public $accessTokenCallAuthHeader;
    
	public $accessTokenCallSignatureBaseString;
}