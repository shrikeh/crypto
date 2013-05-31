<?php
namespace Shrikeh\Crypto\Encryption;

use \Shrikeh\Crypto\Encryption\EncryptionInterface;

abstract class EncryptionAbstract implements EncryptionInterface
{
    /**
     * Available ciphers for this implementation.
     * @var null | array
     */
    protected $availableCiphers;

    /**
     * The cipher to use.
     *
     * @var mixed
     */
    protected $cipher;

    /**
     * As the cipher is immutable, we cache the IV size rather than
     * recalculate it for each request.
     *
     * @var integer
     */
    protected $ivSize;


    /**
     * Return the cipher being used.
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionInterface::getCipher()
     * @return string
     */
    public function getCipher()
    {
        return $this->cipher;
    }

    /**
     * Validate a cipher, set it to the default if none is provided.
     *
     * @param string $cipher
     * @return string
     */
    protected function validateCipher($cipher)
    {
        return in_array($cipher, $this->getAvailableCiphers());
    }

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionInterface::getIvSize()
     */
    public function getIvSize()
    {
        if (null === $this->ivSize) {
            $this->ivSize = $this->getCipherIvSize();
        }
        return $this->ivSize;
    }

    /**
     * Return an array of available ciphers for this implementation.
     *
     * @return array
     */
    public function getAvailableCiphers()
    {
        if (!$this->availableCiphers) {
            $this->availableCiphers = $this->getImplementationCiphers();
        }
        return $this->availableCiphers;
    }

    /**
     * Validate an IV and throw meaningful exceptions if it fails.
     *
     * @param string $iv
     * @throws \InvalidArgumentException
     * @return boolean
     */
    public function validateIv($iv)
    {
        if (!$iv) {
            throw new \InvalidArgumentException(
                'It is bad practice to supply an empty IV'
            );
        }
        $expectedSize = $this->getIvSize();
        if (strlen($iv) < $expectedSize) {
            throw new \InvalidArgumentException(
                "The IV is too short for this cipher, it should be at least $expectedSize bytes"
            );
        }
        return true;
    }

    /**
     * Get the underlying implementation's available ciphers.
     *
     * @return array
     */
    abstract protected function getImplementationCiphers();

    /**
     * Get the underlying implementation's iv size for the given cipher.
     *
     * @return integer
     */
    abstract public function getCipherIvSize();
}
