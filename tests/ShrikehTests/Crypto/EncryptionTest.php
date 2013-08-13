<?php
namespace ShrikehTests\Crypto;

use \stdClass;
use \PHPUnit_Framework_TestCase as TestCase;
use \Shrikeh\Crypto\Encryption;
use \Shrikeh\Crypto\Cipher\Mcrypt;

class EncryptionTest extends TestCase
{
    /**
     *
     **/
    public function testToAndFromEncrypt()
    {
        $cipher = new Mcrypt(MCRYPT_RIJNDAEL_128);

        $data = new stdClass();

        $data->foo = 'bar';
        $key = 'wibble';

        $string64Encoded = Encryption::toEncrypted($data, $key, $cipher);
        $this->assertInternalType('string', $string64Encoded);
        $this->assertSame(1, (int) $string64Encoded[0]);

        $decrypted64 = Encryption::fromEncrypted($string64Encoded, $key);
        $this->assertEquals($data, $decrypted64);

        $string = Encryption::toEncrypted($data, $key, $cipher, false);
        $this->assertSame(0, (int) $string[0]);
        $decrypted = Encryption::fromEncrypted($string, $key);
        $this->assertEquals($data, $decrypted);
    }
}
