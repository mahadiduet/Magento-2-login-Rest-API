<?php
namespace Admin\Login\Api;

interface LoginInterface
{
    /**
     * @param string $token_code
     * @param string $store_code
     * @param string $store_email
     * @return string
     */
    public function login($token_code, $store_code, $store_email);
}
