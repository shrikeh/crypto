<?php
namespace Shrikeh\Crypto\Encryption;

interface EncryptionInterface
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
     * @param mixed $data
     * @param string $password
     * @param string $cipher
     * @param string $iv
     * @param boolean $base64Encode Whether to base64_encode the data
     * @return string The encrypted data
     */
    public function encrypt($data, $key, $iv, $base64Encode = true);

    /**
     * Decrypt and unserialize an encrypted string.
     *
     * @param string $encrypted
     * @param string $password
     * @param string $cipher
     * @param string $iv
     * @param boolean $base64Decode Whether to base64_encode the encrypted data
     * @return mixed The unserialized, decrypted data
     */
    public function decrypt($encrypted, $password, $iv, $base64Decode = true);

    /**
     * Return the default cipher for this implementation.
     *
     * @return string
     */
    public function getCipher();

    /**
     * Return a list of available ciphers.
     * @return array
     */
    public function getAvailableCiphers();
}
