<?php
namespace Shrikeh\Crypto\Cipher;

use \Shrikeh\Crypto\Cipher\CipherAbstract;

class OpenSSL extends CipherAbstract
{
    private $padding;

    /**
     * Constructor.
     *
     * @param string $algorithm
     * @param integer $padding
     * @throws \InvalidArgumentException If not a known cipher
     */
    public function __construct(
        $algorithm = 'aes-256-cbc',
        $padding = 0
    ) {
        $this->padding = $padding;
        if (!$this->validateAlgorithm($algorithm)) {
            throw new \InvalidArgumentException("Cipher $algorithm is not a known algorithm");
        }
        $this->algorithm = $algorithm;
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
    public function getAlgorithmIvSize()
    {
        return openssl_cipher_iv_length($this->getAlgorithm());
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
            $this->getAlgorithm(),
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
            $this->getAlgorithm(),
            $key,
            $this->getPadding(),
            $iv
        );
        return unserialize($decrypted);
    }

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionAbstract::getImplementationAlgorithms()
     */
    protected function getImplementationAlgorithms()
    {
        return openssl_get_cipher_methods();
    }
}
