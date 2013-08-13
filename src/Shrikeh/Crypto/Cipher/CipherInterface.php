<?php
namespace Shrikeh\Crypto\Cipher;

interface CipherInterface
{
    /**
     * Return the size of the initialization vector.
     *
     * @return integer
     */
    public function getIvSize();

    /**
     * Create a pseudo-random initialization vector.
     *
     * @return integer
     */
    public function createIv();



    /**
     * Encrypt some data.
     *
     * @param mixed   $data The data to encrypt
     * @param string  $key The hash to encrypt with
     * @param string  $iv The initialization vector
     * @param boolean $base64Encode Whether to base64_encode the data
     * @return string The encrypted data
     */
    public function encrypt($data, $key, $iv, $base64Encode = true);

    /**
     * Decrypt and unserialize an encrypted string.
     *
     * @param string  $encrypted The encryptd data
     * @param string  $key The hash used to encrypt
     * @param string  $iv The initialization vector
     * @param boolean $base64Decode Whether to base64_encode the encrypted data
     * @return mixed  The unserialized, decrypted data
     */
    public function decrypt($encrypted, $key, $iv, $base64Decode = true);

    /**
     * Return the default cipher for this implementation.
     *
     * @return string
     */
    public function getAlgorithm();

    /**
     * Return a list of available ciphers.
     * @return array
     */
    public function getAvailableAlgorithms();
}
