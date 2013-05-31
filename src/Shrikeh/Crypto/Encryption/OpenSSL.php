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
        if (!$this->validateCipher($cipher)) {
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
    public function getCipherIvSize()
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
     * Encrypt some data.
     *
     * @param mixed   $data The data to encrypt
     * @param string  $key The hash to encrypt with
     * @param string  $iv The initialization vector
     * @param boolean $base64Encode Whether to base64_encode the data
     * @return string The encrypted data
     */
    public function encrypt($data, $key, $iv, $base64Encode = true)
    {
        $this->validateIv($iv);

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
     * Decrypt and unserialize an encrypted string.
     *
     * @param string  $encrypted The encryptd data
     * @param string  $key The hash used to encrypt
     * @param string  $iv The initialization vector
     * @param boolean $base64Decode Whether to base64_encode the encrypted data
     * @return mixed  The unserialized, decrypted data
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
