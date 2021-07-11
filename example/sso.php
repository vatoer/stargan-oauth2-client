<?php 
session_start();
require dirname(__DIR__, 1) . '/vendor/autoload.php';

use Stargan\OAuth2\Client\Provider\Stargan;

use Jose\Component\Core\JWK;
use Jose\Easy\Load;
use Jose\Component\KeyManagement\JWKFactory;

$provider = new Stargan([
    'verify' => false,
    'clientId'     => '427a36069bf7478b2412f48fb0fd0938',
    'clientSecret' => 'bfa1bc762110cf89ceefa46ad2ff87df685646290f5ac370c783b869256e758f84384f9619b7c5c15f179f4936d6c2f9a6805a32c1887cec1f6c5e2512f64ab0',
    'redirectUri'  => 'https://localhost:8000/sso.php',
    //'prompt' => 'none' #uncomment this if you want ignore user consent page
], [
    'httpClient'
]);

$provider->setAuthorizeUrl("https://identity.ssolab/authorize"); // set your authorizeurl
$provider->setTokenUrl("https://identity.ssolab/token"); // set your token server url
$provider->setResourceOwnerUrl("https://userprofile.ssolab/info?fqdn=abcd.example.com"); // fqdn=abcd.example.com this your own implementation query

/**
you can also try here 
username : stargan 
password : secretpass

$provider->setAuthorizeUrl("https://identity.starganteknologi.com/authorize"); // set your authorizeurl
$provider->setTokenUrl("https://identity.starganteknologi.com/token"); // set your token server url
$provider->setResourceOwnerUrl("https://userprofile.starganteknologi.com/info?fqdn=abcd.example.com"); // fqdn=abcd.example.com this your own implementation query
*/

$guzzyClient = new GuzzleHttp\Client([
  'defaults' => [
      \GuzzleHttp\RequestOptions::CONNECT_TIMEOUT => 5,
      \GuzzleHttp\RequestOptions::ALLOW_REDIRECTS => true
  ],
  \GuzzleHttp\RequestOptions::VERIFY => false,
  \GuzzleHttp\RequestOptions::HEADERS => ["Accept" => "application/ld+json"],
]);

$provider->setHttpClient($guzzyClient);

if (!empty($_GET['error'])) {

  // Got an error, probably user denied access
  exit('Got error: ' . htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8'));
} elseif (empty($_GET['code'])) {

  // If we don't have an authorization code then get one
  $authUrl = $provider->getAuthorizationUrl();
  $_SESSION['oauth2state'] = $provider->getState();
  header('Location: ' . $authUrl);
  exit;
} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

  // State is invalid, possible CSRF attack in progress
  unset($_SESSION['oauth2state']);
  exit('Invalid state');
} else {



  // Try to get an access token (using the authorization code grant)
  $token = $provider->getAccessToken('authorization_code', [
      'code' => $_GET['code']
  ]);


  //var_dump($token);


  //var_dump($token->getToken());

  $jwt = $token->getToken();
  //$jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJjMTJlZThkZDRkZmQ2MmM5YzI5OTE2NjQ5NDE3NDk0MSIsImp0aSI6IjBlYWJjNDRiNmJiZWE2MGRkYjgzZDFmZGRjYTMzNmUwN2M5M2E5YWUxOTEwZWI0MjFhYjNhZDEwODA4OTE0MWYyZjU3NTY5OWEzOTZlNzE4IiwiaWF0IjoxNjI0NDA1OTE4LjQ0MTU4MiwibmJmIjoxNjI0NDA1OTE4LjQ0MTU5NiwiZXhwIjoxNjI0NDA5NTE4LjQwMjQyMSwic3ViIjoidXNlcjIiLCJzY29wZXMiOlsicmVhZCIsInByb2ZpbGUiLCJlbWFpbCJdfQ.qNZVNRjBQtdj0JsE3SUwYtcZAj_VN4H_iSxf2V6Gb0LFRO0Ov5dEPStF_ijo0S0aNAH3vYmuf6lZoyUhQRNNQDxL6SEAhr0u4-eITRGis-Da1vxJm9_4VsWVosQg6jsUwh7oOYZx';

  $text = <<<TXT
    <textarea id="w3review" name="w3review" rows="4" cols="50">
    $jwt
    </textarea>
  TXT;

  //echo $text;

  cekJwt($jwt);

  //exit;

  // Optional: Now you have a token you can look up a users profile data
  try {

      // We got an access token, let's now get the owner details
      $ownerDetails = $provider->getResourceOwner($token);

      var_dump($ownerDetails->getRoles());
      exit;

      // Use these details to create a new profile
      // printf('Hello %s!', $ownerDetails->getFirstName());

  } catch (Exception $e) {

      // Failed to get user details
      exit('Something went wrong: '.$e->getCode() . $e->getMessage());
  }

  // Use this to interact with an API on the users behalf
  echo "<br> TOKEN <br>";
  echo $token->getToken();
  echo "<br> END- TOKEN <br>";
  // Use this to get a new access token if the old one expires
  echo $token->getRefreshToken();

  // Unix timestamp at which the access token expires
  echo $token->getExpires();
}



function cekJwt($token)
{
  sleep(1);

  $pathToKeyFile = dirname(__DIR__, 1) . '/ssl/public.key';

  $key = JWKFactory::createFromKeyFile(
      $pathToKeyFile, // The filename
      'Secret',                   // Secret if the key is encrypted
      [
          'use' => 'sig',         // Additional parameters
      ]
  );

  try {
    $jwt = Load::jws($token) // We want to load and verify the token in the variable $token
        ->algs(['RS256', 'RS512']) // The algorithms allowed to be used
        ->exp() // We check the "exp" claim
        ->iat(1000) // We check the "iat" claim. Leeway is 1000ms (1s)
        ->nbf() // We check the "nbf" claim
        ->aud('427a36069bf7478b2412f48fb0fd0938') // Allowed audience
        //->iss('issuer') // Allowed issuer
        //->sub('admin') // Allowed subject
        //->jti('4bd54df921457acc1509e6e9159b45bbeeb4a5713731f267435bf9b6c9b04d9936b3132219af3adc') // Token ID
        ->key($key) // Key used to verify the signature
        ->run(); // Go!

        //var_dump($token);

        //var_dump( date('r', $jwt->claims->exp() ) );
        //var_dump( date('r', $jwt->claims->iat() ) );
        //var_dump( date('r', $jwt->claims->nbf() ) );

        //var_dump ($jwt->claims->all()); // All claims (array)


    ;
  } catch (\Exception $e) {
    var_dump($e->getMessage());
    exit;
  }
}