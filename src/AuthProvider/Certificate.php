<?php

/*
 * This file is part of the Pushok package.
 *
 * (c) Arthur Edamov <edamov@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Pushok\AuthProvider;

use Pushok\AuthProviderInterface;
use Pushok\Request;

/**
 * Class Token
 * @package Pushok\AuthProvider
 *
 * @see http://bit.ly/communicating-with-apns
 */
class Certificate implements AuthProviderInterface
{
    private $keyFilePath;
    
    /**
     * setter for keyFilePath
     *
     * @param mixed $value
     * @return self
     */
    public function setKeyFilePath($value): Certificate
    {
        $this->keyFilePath = $value;
        return $this;
    }
    
    /**
     * getter for keyFilePath
     * 
     * @return mixed return value for 
     */
    public function getKeyFilePath(): ?string
    {
        return $this->keyFilePath;
    }
    
    private $caCertFilePath;
    
    /**
     * setter for caCertFilePath
     *
     * @param mixed $value
     * @return self
     */
    public function setCaCertFilePath($value): Certificate
    {
        $this->caCertFilePath = $value;
        return $this;
    }
    
    /**
     * getter for caCertFilePath
     * 
     * @return mixed return value for 
     */
    public function getCaCertFilePath(): ?string
    {
        return $this->caCertFilePath;
    }
    
    private $certFilePath;
    
    /**
     * setter for certFilePath
     *
     * @param mixed $value
     * @return self
     */
    public function setCertFilePath($value): Certificate
    {
        $this->certFilePath = $value;
        return $this;
    }
    
    /**
     * getter for certFilePath
     * 
     * @return mixed return value for 
     */
    public function getCertFilePath(): ?string
    {
        return $this->certFilePath;
    }
    
    private $certPassword;
    
    /**
     * setter for certPassword
     *
     * @param mixed $value
     * @return self
     */
    public function setCertPassword($value): Certificate
    {
        $this->certPassword = $value;
        return $this;
    }
    
    /**
     * getter for certPassword
     * 
     * @return mixed return value for 
     */
    public function getCertPassword(): ?string
    {
        return $this->certPassword;
    }

    /**
     * Create Certificate Auth Provider.
     *
     * @param array $options
     * @return Token
     */
    public static function create(array $options): Certificate
    {
        $token = new self;
        $token->keyFilePath = $options['key_file_ath'];
        $token->caCertFilePath = $options['ca_cert_File_ath'];
        $token->certFilePath = $options['cert_file_path'];
        
        if (isset($options['cert_password'])) {
            $token->certPassword = $options['cert_password'] ?: null;
        }
        
        return $token;
    }

    /**
     * Authenticate client.
     *
     * @param Request $request
     */
    public function authenticateClient(Request $request) : void
    {
        if ($this->keyFilePath === null) {
            throw new \Exception('Invalid keyFilePath value, it is null. This property is required, please initialize it.');
        }

        if ($this->caCertFilePath === null) {
            throw new \Exception('Invalid caCertFilePath value, it is null. This property is required, please initialize it.');
        }

        if ($this->certFilePath === null) {
            throw new \Exception('Invalid certFilePath value, it is null. This property is required, please initialize it.');
        }
        
        $optionsToSet = [
            CURLOPT_SSLKEY => $this->keyFilePath,
            CURLOPT_CAINFO => $this->caCertFilePath,
            CURLOPT_SSLCERT => $this->certFilePath,
        ];
        
        if ($this->certPassword !== null) {
            $optionsToSet[CURLOPT_SSLCERTPASSWD] = $this->certPassword;
        }
        
        $request->addOptions($optionsToSet);
    }
}
