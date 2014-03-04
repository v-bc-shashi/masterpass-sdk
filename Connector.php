<?php

require 'Models/RequestTokenResponse.php';

require 'Models/AccessTokenResponse.php';


class Connector
{
    const AMP =  "&";

    const QUESTION = "?";

    const EMPTY_STRING = "";

    const EQUALS = "=";

    const DOUBLE_QUOTE = '"';

    const COMMA = ',';

    const ENCODED_TILDE = '%7E';

    const TILDE = '~';

    const COLON = ':';

    const SPACE = ' ';

    const UTF_8 = 'UTF-8';

    const V1 = 'v1';

    const OAUTH_START_STRING = 'OAuth ';

    const REALM = 'realm';

    const ACCEPT = 'Accept';

    const CONTENT_TYPE = 'Content-Type';

    const SSL_CA_CER_PATH_LOCATION = '/SSLCerts/EnTrust/cacert.pem';

    const POST = "POST";

    const GET = "GET";

    const PKEY = 'pkey';

    const STRNATCMP = "strnatcmp";

    const SHA1 = "SHA1";

    const APPLICATION_XML = "application/xml";

    const AUTHORIZATION = "Authorization";

    const OAUTH_BODY_HASH = "oauth_body_hash";

    const BODY = "body";
    // Signature Base String
    const OAUTH_SIGNATURE = "oauth_signature";

    const OAUTH_CONSUMER_KEY = 'oauth_consumer_key';

    const OAUTH_NONCE = 'oauth_nonce';

    const SIGNATURE_METHOD = 'oauth_signature_method';

    const OAUTH_TIMESTAMP = 'oauth_timestamp';

    const OAUTH_CALLBACK = "oauth_callback";

    const OAUTH_SIGNATURE_METHOD = 'oauth_signature_method';
    //Request Token Response
    const XOAUTH_REQUEST_AUTH_URL = 'xoauth_request_auth_url';

    const OAUTH_CALLBACK_CONFIRMED = "oauth_callback_confirmed";

    const OAUTH_EXPRIES_IN = "oauth_expires_in";

    const OAUTH_TOKEN_SECRET = "oauth_token_secret";

    // Callback URL paramenters
    const OAUTH_TOKEN = "oauth_token";

    const OAUTH_VERIFIER = "oauth_verifier";

    const CHECKOUT_RESOURCE_URL = "checkout_resource_url";
    // Redirect Parameters
    const CHECKOUT_IDENTIFIER = 'checkout_identifier';

    const ACCEPTABLE_CARDS = 'acceptable_cards';

    const OAUTH_VERSION = 'oauth_version';

    const VERSION = 'version';

    const SUPPRESS_SHIPPING_ADDRESS = 'suppress_shipping_address';

    const ACCEPT_REWARDS_PROGRAM = 'accept_reward_program';

    const SHIPPING_LOCATION_PROFILE = 'shipping_location_profile';

    const WALLET_SELECTOR = 'wallet_selector_bypass';

    const DEFAULT_XMLVERSION = "v1";

    const AUTH_LEVEL = "auth_level";

    const BASIC = "basic";

    const XML_VERSION_REGEX = "/v[0-9]+/";
    // Srings to detect errors in the service calls
    const ERRORS_TAG = "<Errors>";

    const HTML_TAG = "<html>";

    const HTML_BODY_OPEN = '<body>';

    const HTML_BODY_CLOSE = '</body>';
    // Error Messages
    const EMPTY_REQUEST_TOKEN_ERROR_MESSAGE = 'Invalid Request Token';

    const INVAILD_AUTH_URL = 'Invalid Auth Url';

    const POSTBACK_ERROR_MESSAGE = 'Postback Transaction Call was unsuccessful';
    //Connection Strings
    const CONTENT_TYPE_APPLICATION_XML = 'Content-Type: application/xml';

    const SSL_ERROR_MESSAGE = "SSL Error Code: %s %sSSL Error Message: %s";
    // Our OAuth session instance.
    private $oAuthRequester;

    public $signatureBaseString;

    public $authHeader;

    public $consumerKey;

    public $requestUrl;

    private $shoppingCartUrl;

    public $accessUrl;

    public $callBackUrl;

    public $postbackurl;

    public $realm = 'eWallet'; // This value is static

    private $privateKey;

    private $checkoutIdentifier;

    public $keystorePath;

    public $keystorePassword;

    public $oauthSecrets;

    private $version = '1.0';

    private $signatureMethod = 'RSA-SHA1';
    // Returned by the getRequestToken method.
    private $requestTokenInfo;

    public function __construct($consumerKey)
    {
        $this->consumerKey = $consumerKey;
    }


    /**
     * SDK:
     * This constructor allows the caller to provide a keystore path and keystore password
     * from which to load a keystore's private key.
     *
     * @param String $consumerKey      consumerKey
     * @param String $keystorePath     keystorePath
     * @param String $keystorePassword keystorePassword
     *
     * @return Object
     *
     */
    public static function connectorFromKeystore($consumerKey, $keystorePath, $keystorePassword)
    {
        $instance->consumerKey = $consumerKey;

        $instance->keystorePath = $keystorePath;

        $instance->keystorePassword = $keystorePassword;

        return $instance;
    }


    /**
     * SDK:
     * This constructor allows the caller to provide a preloaded private key for use when
     * OAuth calls are made.
     *
     * @param String $consumerKey consumerKey
     * @param String $privateKey  privateKey
     *
     * @return Object
     */
    public static function connectorFromPrivateKey($consumerKey, $privateKey)
    {
        $instance = new self($consumerKey);

        $instance->consumerKey = $consumerKey;

        $instance->privateKey = $privateKey;

        return $instance;

    }


    /**
     * SDK:
     * This method gets a request token and constructs the redirect URL
     *
     * @param String  $requestUrl              url
     * @param String  $callbackUrl             url
     * @param unknown $acceptableCards         acceptableCards
     * @param String  $checkoutProjectId       checkoutProjectId
     * @param unknown $xmlVersion              xmlVersion
     * @param unknown $shippingSupression      shippingSupression
     * @param unknown $rewardsProgram          rewardsProgram
     * @param unknown $authLevelBasic          authLevelBasic
     * @param unknown $shippingLocationProfile shippingLocationProfile
     * @param unknown $walletSelector          walletSelector
     *
     * @return Output is a RequestTokenResponse object containing all data returned from this method
     *
     */
    public function getRequestTokenAndRedirectUrl($requestUrl, $callbackUrl, $acceptableCards, $checkoutProjectId, $xmlVersion, $shippingSupression, $rewardsProgram, $authLevelBasic, $shippingLocationProfile, $walletSelector)
    {
        $return = $this->getRequestToken($requestUrl, $callbackUrl);

        $return->redirectURL = $this->getConsumerSignInUrl($acceptableCards, $checkoutProjectId, $xmlVersion, $shippingSupression, $rewardsProgram, $authLevelBasic, $shippingLocationProfile, $walletSelector);

        return $return;
    }


    /**
     * SDK:
     * This method posts the Shopping Cart data to MasterCard services
     * and is used to display the shopping cart in the wallet site.
     *
     * @param String  $shoppingCartUrl Url
     * @param unknown $ShoppingCartXml ShoppingCartXml
     *
     * @return Output is the response from MasterCard services
     *
     */
    public function postShoppingCartData($shoppingCartUrl, $ShoppingCartXml)
    {
        $params = array(Connector::OAUTH_BODY_HASH => $this->generateBodyHash($ShoppingCartXml));

        $response = $this->doRequest($params, $shoppingCartUrl, Connector::POST, $ShoppingCartXml);

        return  $response;
    }


    /**
     * SDK:
     * This method captures the Checkout Resource URL and Request Token Verifier
     * and uses these to request the Access Token.
     *
     * @param String  $accessUrl    accessUrl
     * @param String  $requestToken requestToken
     * @param unknown $verifier     verifier
     *
     * @return Output is Access Token
     *
     */
    public function GetAccessToken($accessUrl, $requestToken, $verifier)
    {
        $params = array(
                Connector::OAUTH_VERIFIER => $verifier,
                Connector::OAUTH_TOKEN => $requestToken
        );

        $return = new AccessTokenResponse();

        $response = $this->doRequest($params, $accessUrl, Connector::POST, null);

        $token = $this->parseConnectionResponse($response);

        $return->accessToken = $token[Connector::OAUTH_TOKEN];

        $return->oauthSecret = $token[connector::OAUTH_TOKEN_SECRET];

        return $return;
    }
    

    /**
     * SDK:
     * This method retrieves the payment and shipping information
     * for the current user/session.
     *
     * @param unknown $checkoutResourceUrl Url
     * @param unknown $accessToken         accessToken
     *
     * @return Output is the Checkout XML string containing the users billing and shipping information
     *
     */
    public function GetPaymentShippingResource($checkoutResourceUrl, $accessToken)
    {
        $params = array(Connector::OAUTH_TOKEN => $accessToken);

        $response = $this->doRequest($params, $checkoutResourceUrl, Connector::GET, null);

        return  $response;
    }


    /**
     * This method submits the receipt transaction list to MasterCard as a final step
     * in the Wallet process.
     *
     * @param String  $postbackurl          Url
     * @param unknown $merchantTransactions merchantTransactions
     *
     * @return Output is the response from MasterCard services
     *
     */
    public function PostCheckoutTransaction($postbackurl, $merchantTransactions)
    {
        $params = array(Connector::OAUTH_BODY_HASH => $this->generateBodyHash($merchantTransactions));

        $response = $this->doRequest($params, $postbackurl, Connector::POST, $merchantTransactions);

        return  $response;
    }


    /**
     * Encodes all ASCII character to there decimal encodings
     *
     * @param String $str string
     *
     * @return String
     *
     */
    public static function AllHtmlEncode($str)
    {
        if (empty($str)) {
            return $str;
        } else {
            // get rid of existing entities else double-escape
            $str = html_entity_decode(stripslashes($str), ENT_QUOTES, Connector::UTF_8);

            $ar = preg_split('/(?<!^)(?!$)/u', $str);  // return array of every multi-byte character

            foreach ($ar as $c) {
                $o = ord($c);

                if ((strlen($c) > 127) || ($o > 127)) { /* multi-byte [unicode] || Encodes everything above ascii 127 */
                    // convert to numeric entity
                    $c = mb_encode_numericentity($c, array(0x0, 0xffff, 0, 0xffff), Connector::UTF_8);
                }

                $str2 .= $c;
            }

            return $str2;
        }
    }


    /**
     * Method to HTML encode the descriptions in the shopping cart object
     *
     * @param SimpleXMLElement $shoppingCartData shoppingCartData
     *
     * @return SimpleXMLElement - HTML encoded descriptions
     *
     */
    public static function encodeShoppingCartRequest(SimpleXMLElement $shoppingCartData)
    {
        foreach ($shoppingCartData->ShoppingCart->ShoppingCartItem as $item) {
            $item->Description = Connector::AllHtmlEncode((string)$item->Description);
        }

        return $shoppingCartData;
    }


    /**
     * Method to convert strings 'true' and 'false' to a boolean value
     * If parameter string is not 'true' (case insensitive), then false will be returned
     *
     * @param String $str string
     *
     * @return boolean
     *
     */
    public static function str_to_bool($str)
    {
        return (strcasecmp($str, true) == 0)? true : false;
    }


    /*************** Private Methods *****************************************************************************************************************************/
    /**
     * SDK:
     * Get the user's request token and store it in the current user session.
     *
     * @param String $requestUrl  requestUrl
     * @param String $callbackUrl redirectUrl
     *
     * @return RequestTokenResponse
     *
     */
    private function GetRequestToken($requestUrl, $callbackUrl)
    {
        $params = array(Connector::OAUTH_CALLBACK => $callbackUrl);

        $response = $this->doRequest($params, $requestUrl, Connector::POST, null);

        $requestTokenInfo = $this->parseConnectionResponse($response);

        $return = new RequestTokenResponse();

        $return->requestToken = $requestTokenInfo[Connector::OAUTH_TOKEN];

        $return->authorizeUrl =  $requestTokenInfo[Connector::XOAUTH_REQUEST_AUTH_URL];

        $return->callbackConfirmed =  $requestTokenInfo[Connector::OAUTH_CALLBACK_CONFIRMED];

        $return->oauthexpiresIn =  $requestTokenInfo[Connector::OAUTH_EXPRIES_IN];

        $return->oauthSecret =  $requestTokenInfo[Connector::OAUTH_TOKEN_SECRET];

        $this->requestTokenInfo = $return;

        // Return the request token response class.
        return $return;
    }


    /**
     * SDK:
     * Assuming that all due diligence is done and assuming the presence of an established session,
     * successful reception of non-empty request token, and absence of any unanticipated
     * exceptions have been successfully verified, you are ready to go to the authorization
     * link hosted by MasterCard.
     *
     * @param unknown $acceptableCards         acceptableCards
     * @param String  $checkoutProjectId       checkoutProjectId
     * @param String  $xmlVersion              xmlVersion
     * @param unknown $shippingSupression      shippingSupression
     * @param unknown $rewardsProgram          rewardsProgram
     * @param unknown $authLevelBasic          authLevelBasic
     * @param unknown $shippingLocationProfile location
     * @param unknown $walletSelector          walletselector
     *
     * @return string - URL to redirect the user to the MasterPass wallet site
     *
     */
    private function GetConsumerSignInUrl($acceptableCards, $checkoutProjectId, $xmlVersion, $shippingSupression, $rewardsProgram, $authLevelBasic, $shippingLocationProfile, $walletSelector)
    {
        $baseAuthUrl = $this->requestTokenInfo->authorizeUrl;

        $xmlVersion = strtolower($xmlVersion);

        // Use v1 if xmlVersion does not match correct patern
        if (!preg_match(Connector::XML_VERSION_REGEX, $xmlVersion)) {
            $xmlVersion = Connector::DEFAULT_XMLVERSION;
        }

        $token = $this->requestTokenInfo->requestToken;

        if ($token == null || $token == Connector::EMPTY_STRING) {
            throw new Exception(Connector::EMPTY_REQUEST_TOKEN_ERROR_MESSAGE);
        }

        if ($baseAuthUrl == null || $baseAuthUrl == Connector::EMPTY_STRING) {
            throw new Exception(Connector::INVAILD_AUTH_URL);
        }

        // construct the Redirect URL
        $finalAuthUrl = $baseAuthUrl .

        $this->getParamString(Connector::ACCEPTABLE_CARDS, $acceptableCards, true).

        $this->getParamString(Connector::CHECKOUT_IDENTIFIER, $checkoutProjectId) .

        $this->getParamString(Connector::OAUTH_TOKEN, $token).

        $this->getParamString(Connector::VERSION, $xmlVersion);

        // If xmlVersion is v1 (default version), then shipping suppression, rewardsprogram and auth_level are not used
        if (strcasecmp($xmlVersion, Connector::DEFAULT_XMLVERSION) != Connector::V1) {

            if ($shippingSupression == 'true' || $shippingSupression == 'false' ) {
                $finalAuthUrl = $finalAuthUrl.$this->getParamString(Connector::SUPPRESS_SHIPPING_ADDRESS, $shippingSupression);
            }

            if ((int)substr($xmlVersion, 1) >= 4 && $rewardsProgram == 'true') {
                $finalAuthUrl = $finalAuthUrl.$this->getParamString(Connector::ACCEPT_REWARDS_PROGRAM, $rewardsProgram);
            }

            if ($authLevelBasic) {
                $finalAuthUrl = $finalAuthUrl.$this->getParamString(Connector::AUTH_LEVEL, CONNECTOR::BASIC);
            }

            if ((int)substr($xmlVersion, 1) >= 4 && $shippingLocationProfile != null && !empty($shippingLocationProfile)) {
                $finalAuthUrl = $finalAuthUrl.$this->getParamString(Connector::SHIPPING_LOCATION_PROFILE, $shippingLocationProfile);
            }

            if ((int)substr($xmlVersion, 1) >= 5 && $walletSelector == 'true' ) {
                $finalAuthUrl = $finalAuthUrl.$this->getParamString(Connector::WALLET_SELECTOR, $walletSelector);
            }
        }

        return $finalAuthUrl;
    }


    /**
     * SDK:
     * Method to generate the body hash
     *
     * @param unknown $body bodyValue
     *
     * @return string
     *
     */
    private function generateBodyHash($body)
    {
        $sha1Hash = sha1($body, true);

        return base64_encode($sha1Hash);
    }


    /**
     * SDK:
     * Method to create the URL with GET Parameters
     *
     * @param unknown $key        key
     * @param String  $value      value
     * @param boolean $firstParam boolean value
     *
     * @return string
     *
     */
    private function getParamString($key, $value, $firstParam = false)
    {
        $paramString = Connector::EMPTY_STRING;

        if ($firstParam) {
            $paramString .= Connector::QUESTION;
        } else {
            $paramString .= Connector::AMP;
        }

        $paramString .= $key.Connector::EQUALS.$value;

        return $paramString;
    }


    /**
     * This method generates and returns a unique nonce value to be used in
     *    Wallet API OAuth calls.
     *
     * @param Int $length length
     *
     * @return String string
     *
     */
    private function generateNonce($length)
    {
        if (function_exists('com_create_guid') === true) {
            return trim(com_create_guid(), '{}');
        } else {
            $u = md5(uniqid('nonce_', true));

            return substr($u, 0, $length);
        }
    }


    /**
     * Method used to parse the connection response and return a array of the data
     *
     * @param unknown $responseString responseString
     *
     * @return Array with all response parameters
     *
     */
    private function parseConnectionResponse($responseString)
    {
        $token  = array();

        foreach (explode(Connector::AMP, $responseString) as $p) {
            @list($name, $value) = explode(Connector::EQUALS, $p, 2);

            $token[$name] = urldecode($value);
        }

        return $token;
    }


    /**
     *  Method used for all Http connections
     *
     * @param unknown $params        params
     * @param unknown $url           url
     * @param unknown $requestMethod requestMethod
     * @param unknown $body          body
     *
     * @throws Exception - When connection error
     *
     * @return mixed - Raw data returned from the HTTP connection
     *
     */
    private function doRequest($params, $url, $requestMethod, $body=null)
    {
        try {
            return $this->connect($params, $this->realm, $url, $requestMethod, $body);
        } catch (Exception $e) {
            throw $this->checkForErrors($e);
        }
    }


    /**
     * Builds a Auth Header used in connection to MasterPass services
     *
     * @param array   $params        params
     * @param unknown $realm         realm
     * @param unknown $url           url
     * @param unknown $requestMethod requestMethod
     * @param unknown $body          body
     *
     * @return string - Auth header
     *
     */
    private function buildAuthHeaderString($params, $realm, $url, $requestMethod, $body)
    {
        $params = array_merge($this->OAuthParametersFactory(), $params);

        $signature = $this->generateAndSignSignature($params, $url, $requestMethod, $this->privateKey, $body);

        $params[Connector::OAUTH_SIGNATURE] = $signature;

        $startString = Connector::OAUTH_START_STRING;

        if (!empty($realm)) {
            $startString = $startString.Connector::REALM.Connector::EQUALS.Connector::DOUBLE_QUOTE.$realm.Connector::DOUBLE_QUOTE.Connector::COMMA;
        }

        foreach ($params as $key => $value) {
            $startString = $startString.$key.Connector::EQUALS.Connector::DOUBLE_QUOTE.$this->RFC3986urlencode($value).Connector::DOUBLE_QUOTE.Connector::COMMA;
        }

        $this->authHeader = substr($startString, 0, strlen($startString)-1);

        return $this->authHeader;
    }


    /**
     * Method to generate base string and generate the signature
     *
     * @param unknown $params        params
     * @param unknown $url           url
     * @param unknown $requestMethod requestMethod
     * @param unknown $privateKey    privateKey
     * @param unknown $body          body
     *
     * @return string
     *
     */
    private function generateAndSignSignature($params, $url, $requestMethod, $privateKey, $body)
    {
        $baseString = $this->generateBaseString($params, $url, $requestMethod);

        $this->signatureBaseString = $baseString;

        $signature = $this->sign($baseString, $privateKey);

        return $signature;
    }


    /**
     * Method to sign string
     *
     * @param unknown $string     stringValue
     * @param unknown $privateKey keyValue
     *
     * @return string
     *
     */
    private function sign($string, $privateKey)
    {
        $privatekeyid = openssl_get_privatekey($privateKey);

        openssl_sign($string, $signature, $privatekeyid, OPENSSL_ALGO_SHA1);

        return base64_encode($signature);

    }


    /**
     * Method to generate the signature base string
     *
     * @param unknown $params        params
     * @param string  $url           url
     * @param unknown $requestMethod method
     *
     * @return string
     *
     */
    private function generateBaseString($params, $url, $requestMethod)
    {
        $urlMap = parse_url($url);

        $url = $this->formatUrl($url, $params);

        $params = $this->parseUrlParameters($urlMap, $params);

        $baseString = strtoupper($requestMethod).Connector::AMP.$this->RFC3986urlencode($url).Connector::AMP;

        ksort($params);

        $parameters = Connector::EMPTY_STRING;

        foreach ($params as $key => $value) {
            $parameters = $parameters.$key.Connector::EQUALS.$this->RFC3986urlencode($value).Connector::AMP;
        }

        $parameters = $this->RFC3986urlencode(substr($parameters, 0, strlen($parameters)-1));

        return $baseString.$parameters;
    }


    /**
     * Method to parsing utl parameters
     *
     * @param array   $urlMap urlmap
     * @param unknown $params params
     *
     * @return array
     */
    function parseUrlParameters($urlMap, $params)
    {
        if (empty($urlMap['query'])) {
            return $params;
        } else {
            $str = $urlMap['query'];

            parse_str($str, $urlParamsArray);

            return array_merge($params, $urlParamsArray);
        }
    }


    /**
     * Method to foramating url
     *
     * @param array   $url    url
     * @param unknown $params params
     *
     * @return array
     *
     */
    function formatUrl($url, $params)
    {
        if (!parse_url($url)) {
            return $url;
        }

        $urlMap = parse_url($url);

        return $urlMap['scheme'].'://'.$urlMap['host'].$urlMap['path'];
    }


    /**
     * URLEncoder that conforms to the RFC3986 spec.
     * PHP's internal function, rawurlencode, does not conform to RFC3986 for PHP 5.2
     *
     * @param unknown $string string value
     *
     * @return unknown|mixed
     *
     */
    function RFC3986urlencode($string)
    {
        if ($string === false) {
            return $string;
        } else {
            return str_replace(Connector::ENCODED_TILDE, Connector::TILDE, rawurlencode($string)); 
        }
    }


    /**
     * Method to create all default parameters used in the base string and auth header
     *
     * @return array
     *
     */
    private function OAuthParametersFactory()
    {
        $nonce = $this->generateNonce(16);

        $time = time();

        $params = array(Connector::OAUTH_CONSUMER_KEY=>$this->consumerKey,
                        Connector::OAUTH_SIGNATURE_METHOD=>$this->signatureMethod,
                        Connector::OAUTH_NONCE=>$nonce,
                        Connector::OAUTH_TIMESTAMP=>$time,
                        Connector::OAUTH_VERSION=>$this->version
        );

        return $params;
    }


    /**
     * General method to handle all HTTP connections
     *
     * @param unknown $params        request parameters
     * @param unknown $realm         request pealm
     * @param unknown $url           requesturl
     * @param unknown $requestMethod request method
     * @param string  $body          request body
     *
     * @throws Exception - If connection fails or recieves a HTTP status code > 300
     *
     * @return mixed
     *
     */
    private function connect($params, $realm, $url, $requestMethod, $body=null)
    {
        $curl = curl_init($url);
        // Adds the CA cert bundle to authenticate the SSL cert
        curl_setopt($curl, CURLOPT_CAINFO, __DIR__ .Connector::SSL_CA_CER_PATH_LOCATION);

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);

        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true); // This should always be true to secure SSL connections

        curl_setopt($curl, CURLOPT_HTTPHEADER, array(Connector::ACCEPT.Connector::COLON.Connector::SPACE.Connector::APPLICATION_XML, Connector::CONTENT_TYPE.Connector::COLON.Connector::SPACE.Connector::APPLICATION_XML, Connector::AUTHORIZATION.Connector::COLON.Connector::SPACE.$this->buildAuthHeaderString($params, $realm, $url, $requestMethod, $body)));

        if ($requestMethod == Connector::GET) {
            curl_setopt($curl, CURLOPT_HTTPGET, true);
        } else {
            curl_setopt($curl, CURLOPT_POST, true);

            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }

        $result = curl_exec($curl);

        // Check if any error occurred
        if (curl_errno($curl)) {
            throw new Exception(sprintf(Connector::SSL_ERROR_MESSAGE, curl_errno($curl), PHP_EOL, curl_error($curl)), curl_errno($curl));
        }

        // Check for errors and throw an exception
        if ($errorCode = curl_getinfo($curl, CURLINFO_HTTP_CODE) > 300) {
            throw new Exception($result, $errorCode);
        }

        return $result;
    }
    

    /**
     * Method to check for HTML content in the exception message and remove everything except the body
     *
     * @param Exception $e checkout exception
     *
     * @return Exception
     *
     */
    private function checkForErrors(Exception $e)
    {
        if (strpos($e->getMessage(), Connector::HTML_TAG) !== false) {
            $body = substr($e->getMessage(), strpos($e->getMessage(), Connector::HTML_BODY_OPEN)+6, strpos($e->getMessage(), Connector::HTML_BODY_CLOSE));
            return new Exception($body);
        } else {
            return $e;
        }
    }


}
