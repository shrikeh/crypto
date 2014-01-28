<?php
namespace Shrikeh\Crypto\Cipher;

use \Shrikeh\Crypto\Cipher\CipherAbstract;

class Mcrypt extends CipherAbstract
{
    /**
     * Location of the mcrypt algorithms library.
     *
     * @var string
     */
    private $libDir;

    /**
     * The mode for encryption.
     *
     * @var integer
     */
    private $mode;

    /**
     * Constructor.
     *
     * @param string $algorithm
     * @param string $mode
     * @param string $libDir
     * @throws \InvalidArgumentException
     */
    public function __construct(
        $algorithm = MCRYPT_RIJNDAEL_256,
        $mode = MCRYPT_MODE_CBC,
        $libDir = null
    ) {

        $this->mode   = $mode;
        if (null === $libDir) {
            $libDir = ini_get('mcrypt.algorithms_dir');
        }
        $this->libDir = $libDir;

        if (!$this->validateAlgorithm($algorithm)) {
            throw new \InvalidArgumentException("Algorithm $algorithm is not a known algorithm");
        }
        $this->algorithm = $algorithm;
    }

    /**
     * Return the mode, i.e. "CBC"
     *
     * @return string
     */
    public function getMode()
    {
        return $this->mode;
    }


    public function getAlgorithmIvSize()
    {
        return mcrypt_get_iv_size($this->getAlgorithm(), $this->getMode());
    }

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionInterface::createIv()
     */
    public function createIv()
    {
        return mcrypt_create_iv($this->getIvSize(), MCRYPT_DEV_RANDOM);
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

        $encrypted =  mcrypt_encrypt(
            $this->getAlgorithm(),
            $key,
            serialize($data),
            $this->getMode(),
            $iv
        );
        return ($base64Encode) ? base64_encode($encrypted) : $encrypted;
    }

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionAbstract::getImplementationAlgorithms()
     */
    private function getImplementationAlgorithms()
    {
        return mcrypt_list_algorithms($this->libDir);
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
        $decrypted =  mcrypt_decrypt(
            $this->getAlgorithm(),
            $key,
            $encrypted,
            $this->getMode(),
            $iv
        );
        return unserialize($decrypted);
    }
}
