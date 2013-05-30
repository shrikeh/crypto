<?php
namespace Shrikeh\Crypto\Encryption;

use \Shrikeh\Crypto\Encryption\EncryptionAbstract;

class OpenSSL extends EncryptionAbstract
{
    protected $padding;

    /**
     *
     * @param string $cipher
     * @param string $padding
     */
    public function __construct(
        $cipher = 'aes-256-cbc',
        $padding = 0
    ) {
        $this->padding = $padding;
        if (!$this->validateCipher($cipher) ) {
            throw new \InvalidArgumentException("Cipher $cipher is not a known cipher");
        }
        $this->cipher = $cipher;
    }

    /**
     *
     * @return integer
     */
    public function getPadding()
    {
        return $this->padding;
    }

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionInterface::getIvSize()
     */
    public function getIvSize()
    {
        return openssl_cipher_iv_length($this->getCipher());
    }

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionInterface::createIv()
     */
    public function createIv()
    {
      // TODO: Auto-generated method stub
        return openssl_random_pseudo_bytes($this->getIvSize());
    }

    /**
     * Encrypt some data based on the key and initialization vector.
     *
     * @param mixed $data
     * @param string $password
     * @param string $cipher
     * @param string $iv
     */
    public function encrypt($data, $key, $iv, $base64Encode = true)
    {
        $encrypted = openssl_encrypt(
            serialize($data),
            $this->getCipher(),
            $key,
            $this->getPadding(),
            $iv
        );
        return ($base64Encode) ? base64_encode($encrypted) : $encrypted;
    }

    /**
     * Decrypt the data based on a key and initialization vector.
     *
     * @param string  $encrypted
     * @param string  $password
     * @param string  $cipher
     * @param string  $iv
     * @param boolean $base64Decode Whether to base64_decode the encrypted data
     */
    public function decrypt($encrypted, $key, $iv, $base64Decode = true)
    {
         if ($base64Decode) {
             $encrypted = base64_decode($encrypted);
         }
         $decrypted = openssl_decrypt(
             $encrypted,
             $this->getCipher(),
             $key,
             $this->getPadding(),
             $iv
        );
        return unserialize($decrypted);
    }

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionAbstract::getImplementationCiphers()
     */
    protected function getImplementationCiphers()
    {
        return openssl_get_cipher_methods();
    }

}
