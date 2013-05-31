<?php
namespace Shrikeh\Crypto\Cipher;

use \Shrikeh\Crypto\Cipher\CipherInterface;

abstract class CipherAbstract implements CipherInterface
{
    /**
     * Available ciphers for this implementation.
     * @var null | array
     */
    protected $availableAlgorithms;

    /**
     * The cipher to use.
     *
     * @var mixed
     */
    protected $algorithm;

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
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * Validate a cipher, set it to the default if none is provided.
     *
     * @param string $algorithm
     * @return string
     */
    protected function validateAlgorithm($algorithm)
    {
        return in_array($algorithm, $this->getAvailableAlgorithms());
    }

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionInterface::getIvSize()
     */
    public function getIvSize()
    {
        if (null === $this->ivSize) {
            $this->ivSize = $this->getAlgorithmIvSize();
        }
        return $this->ivSize;
    }

    /**
     * Return an array of available ciphers for this implementation.
     *
     * @return array
     */
    public function getAvailableAlgorithms()
    {
        if (!$this->availableAlgorithms) {
            $this->availableAlgorithms = $this->getImplementationAlgorithms();
        }
        return $this->availableAlgorithms;
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
    abstract protected function getImplementationAlgorithms();

    /**
     * Get the underlying implementation's iv size for the given cipher.
     *
     * @return integer
     */
    abstract public function getAlgorithmIvSize();
}
