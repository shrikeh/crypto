<?php
namespace Shrikeh\Crypto;

use \Shrikeh\Crypto\Cipher\CipherInterface;
use \Shrikeh\Crypto\Cipher\Mcrypt;

class Encryption
{
    protected $cipher;

    protected $cipherOptions;

    protected static $separator = '.';

    public static function fromEncrypted($encrypted, $key)
    {
        $base64Decode = (boolean) $encrypted[0];
        $encrypted = substr($encrypted, 1);

        list($cipherDetails, $iv, $data) = explode(self::$separator, $encrypted);

        $cipherDetails = unserialize(base64_decode($cipherDetails));
        $iv = base64_decode($iv);
        $cipher = new Mcrypt($cipherDetails['algorithm'], $cipherDetails['mode']);
        $decrypted = $cipher->decrypt($data, $key, $iv, $base64Decode);
        return $decrypted;
    }

    public static function toEncrypted(
        $data,
        $key,
        CipherInterface $cipher,
        $base64Encode = true
    ) {
        $iv = $cipher->createIv();

        $payload = array(
            'header'    => base64_encode(serialize($cipher->toArray())),
            'iv'        => base64_encode($iv),
            'data'      => $cipher->encrypt($data, $key, $iv, $base64Encode),
        );

        $encrypted = implode(self::$separator, $payload);
        $encrypted = (($base64Encode) ? 1 : 0) . $encrypted;
        return $encrypted;
    }

    /**
     * Constructor.
     *
     * @param array | \Iterator $options
     */
    public function __construct($options = array())
    {
        $this->cipherOptions = $options;
    }

    /**
     *
     * @param mixed $data
     * @param string $key
     * @param string $iv
     * @param boolean $base64Encode
     * @return string
     */
    public function encrypt($data, $key, $iv, $base64Encode = true)
    {
        return $this->getCipher()->encrypt($data, $key, $iv, $base64Encode);
    }


    /**
     * Lazily instantiate a cipher as necessary.
     *
     * @return \Shrikeh\Crypto\Cipher\CipherInterface
     */
    public function getCipher()
    {
        if (!$this->cipher) {
            $this->cipher = new Mcrypt();
        }
        return $this->cipher;
    }
}
