<?php
namespace Shrikeh\Crypto\Encryption;

use \Shrikeh\Crypto\Encryption\EncryptionAbstract;

class Mcrypt extends EncryptionAbstract
{
    /**
     * Location of the mcrypt algorithms library.
     *
     * @var string
     */
    protected $libDir;

    protected $mode;

    public function __construct(
        $cipher = MCRYPT_RIJNDAEL_256,
        $mode   = MCRYPT_MODE_CBC,
        $libDir = null
    ) {

        $this->mode   = $mode;
        if (null === $libDir) {
            $libDir = ini_get('mcrypt.algorithms_dir');
        }
        $this->libDir = $libDir;

        if (!$this->validateCipher($cipher) ) {
            throw new \InvalidArgumentException("Cipher $cipher is not a known cipher");
        }
        $this->cipher = $cipher;
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

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionInterface::getIvSize()
     */
    public function getIvSize()
    {
        return mcrypt_get_iv_size($this->getCipher(), $this->getMode());
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
     * Encrypt some data based on the key and initialization vector.
     *
     * @param mixed $data
     * @param string $password
     * @param string $cipher
     * @param string $iv
     */
    public function encrypt($data, $key, $iv, $base64Encode = true)
    {
        $encrypted =  mcrypt_encrypt(
            $this->getCipher(),
            $key,
            serialize($data),
            $this->getMode(),
            $iv
        );
        return ($base64Encode) ? base64_encode($encrypted) : $encrypted;
    }

    /**
     * (non-PHPdoc)
     * @see \Shrikeh\Crypto\Encryption\EncryptionAbstract::getImplementationCiphers()
     */
    protected function getImplementationCiphers()
    {
        return mcrypt_list_algorithms($this->libDir);
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
        $decrypted =  mcrypt_decrypt(
            $this->getCipher(),
            $key,
            $encrypted,
            $this->getMode(),
            $iv
        );
        return unserialize($decrypted);
    }
}
