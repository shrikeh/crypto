<?php
namespace Shrikeh\Crypto;

class Encryption
{
    protected $cipher;

    public function __construct($implementation, $options = array())
    {
        $this->cipher = new Mcrypt();
    }

    public function encrypt($data, $key, $iv = null, $base64Encode = true)
    {
        if (!$iv) {
            $iv = $this->cipher
        }
    }

    public function getCipher()
}
