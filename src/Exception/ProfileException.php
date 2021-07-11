<?php
/**
 * This file is part of the stargan/oauth2-client library
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright Copyright (c) Fathur Rohman <vatoer.ckplus@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 * @link http://developer.starganteknologi.com/oauth2-client/ Documentation
 * @link https://github.com/vatoer/oauth2-client GitHub
 */

namespace Stargan\OAuth2\Client\Exception;

/**
 * Exception thrown if the profile not match the profile specification.
 */
class ProfileException extends \Exception
{
    /**
     * @var mixed
     */
    protected $response;

    /**
     * @param string $message
     * @param int $code
     * @param array|string $response The response body
     */
    public function __construct($message, $code, $response)
    {
        $this->response = $response;

        parent::__construct($message, $code);
    }

    /**
     * Returns the exception's response body.
     *
     * @return array|string
     */
    public function getResponseBody()
    {
        return $this->response;
    }
}
