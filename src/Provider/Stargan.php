<?php

/**
 * this file is part of Stargan oauth2 client
 * Stargan provider
 *
 * @author fathur rohman <fathur.rohman@Stargan.go.id>
 *
 */

namespace Stargan\OAuth2\Client\Provider;

use League\OAuth2\Client\Exception\HostedDomainException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use UnexpectedValueException;

class Stargan extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * @var string If set, this will be sent as the "access_type" parameter.
     * @link
     */
    protected $accessType;

    /**
     * @var string If set, this will be sent as the "prompt" parameter.
     */
    protected $prompt;

    /**
     * @var array List of scopes that will be used for authentication.
     * @link https://ssodeveloper.Stargan.go.id/identity/scopes
     */
    protected $scopes = [];

    protected $authorizeUrl = "https://nama.domain.com/authorize";
    protected $tokenUrl = "https://nama.domain.com/token";
    protected $resourceOwnerUrl = "https://resource.owner.com/userinfo";
    protected $ownerClass;

    public function setAuthorizeUrl($url): self
    {
        $this->authorizeUrl = $url;
        return $this;
    }

    public function setTokenUrl($url): self
    {
        $this->tokenUrl = $url;
        return $this;
    }

    public function setResourceOwnerUrl($url): self
    {
        $this->resourceOwnerUrl = $url;
        return $this;
    }

    public function getBaseAuthorizationUrl(): string
    {
        return $this->authorizeUrl;
    }

    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->tokenUrl;
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->resourceOwnerUrl;
    }

    /**
     * Requests and returns the resource owner of given access token.
     *
     * @param  AccessToken $token
     * @return StarganUser
     */
    public function getResourceOwner(AccessToken $token):?StarganUser
    {
        $response = $this->fetchResourceOwnerDetails($token);

        return $this->createResourceOwner($response, $token);
    }

    public function getResourceOwnerExtended(AccessToken $token, StarganUserInterface $owner): ?StarganUserInterface
    {
        $response = $this->fetchResourceOwnerDetails($token);
        return $this->createResourceOwnerExtended($response, $token, $owner);
    }

    /**
     * Request and returns the raw resource owner of given access token, it should be JSON
     *
     * @param AccessToken $token
     * @return void
     */
    public function getRawResourceOwner(AccessToken $token)
    {
        $response = $this->fetchResourceOwnerDetails($token);
        return $response;
    }

    /**
     * Request and returns the Profile owner of given access token, it should be JSON
     *
     * @param AccessToken $token
     * @return Profile
     */
    public function getProfileOwner(AccessToken $token)
    {
        $response = $this->fetchResourceOwnerDetails($token);
        return new Profile($response);
    }

    protected function getAuthorizationParameters(array $options): array
    {

        if (empty($options['access_type']) && $this->accessType) {
            $options['access_type'] = $this->accessType;
        }

        if (empty($options['prompt']) && $this->prompt) {
            $options['prompt'] = $this->prompt;
        }

        // Default scopes MUST be included for OpenID Connect.
        // Additional scopes MAY be added by constructor or option.
        $scopes = array_merge($this->getDefaultScopes(), $this->scopes);

        if (!empty($options['scope'])) {
            $scopes = array_merge($scopes, $options['scope']);
        }

        $options['scope'] = array_unique($scopes);

        $options = parent::getAuthorizationParameters($options);

        // The "approval_prompt" MUST be removed as it is not supported by Stargan, use "prompt" instead:
        // https://ssodevelopers.Stargan.com/identity/oauth2/openid-connect#prompt
        unset($options['approval_prompt']);

        return $options;
    }

    protected function getDefaultScopes(): array
    {
        return [
            'read',
            'profile',
            'email',
        ];
    }

    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    protected function checkResponse(ResponseInterface $response, $data): void
    {
        // @codeCoverageIgnoreStart
        if (empty($data['error'])) {
            return;
        }
        // @codeCoverageIgnoreEnd

        $code = 0;
        $error = $data['error'];

        if (is_array($error)) {
            $code = $error['code'];
            $error = $error['message'];
        }

        throw new IdentityProviderException($error, $code, $data);
    }

    protected function createResourceOwner(array $response, AccessToken $token): StarganUser
    {
        $user = new StarganUser();
        $user->setAccout($response);
        return $user;
    }

    /**
     * variant function from createResourceOwner
     * we use this class if we want resource owner implement other class like UserInterface in symfony
     *
     * @param array $response
     * @param AccessToken $token
     * @param StarganUserInterface $owner
     * @return StarganUserInterface
     */
    protected function createResourceOwnerExtended(array $response, AccessToken $token, StarganUserInterface $owner): StarganUserInterface
    {
        return $owner->setAccout($response);
    }

    
    /**
     * Returns a prepared request for requesting an access token.
     *
     * @param array $params Query string parameters
     * @return RequestInterface
     */
    protected function getAccessTokenRequest(array $params)
    {
        $method  = $this->getAccessTokenMethod();
        $url     = $this->getAccessTokenUrl($params);
        $options = $this->optionProvider->getAccessTokenOptions($this->getAccessTokenMethod(), $params);

        $options['verify'] = false;
        return $this->getRequest($method, $url, $options);
    }
}
