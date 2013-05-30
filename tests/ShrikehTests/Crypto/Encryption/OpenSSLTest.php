<?php
namespace ShrikehTests\Crypto\Encryption;

use \stdClass;

use \PHPUnit_Framework_TestCase as TestCase;
use \Shrikeh\Crypto\Encryption\OpenSSL;

class OpenSSLTest extends TestCase
{
    /**
     * @test
     */
    public function testCrypt()
    {
        $cipher = 'aes-256-cbc';
        $crypt = new OpenSSL($cipher);
        $this->assertSame($cipher, $crypt->getCipher());

        $data = new stdClass();
        $data->foo = 'bar';
        $key = 'wibble';
        $ivSize = openssl_cipher_iv_length($cipher);
        $iv = openssl_random_pseudo_bytes($ivSize);

        $encrypt64 = $crypt->encrypt($data, $key, $iv);
        $this->assertNotEmpty($encrypt64);
        $this->assertNotEquals($encrypt64, $data);

        $decrypt64 = $crypt->decrypt($encrypt64, $key, $iv);
        $this->assertEquals($data, $decrypt64);

        $encrypt = $crypt->encrypt($data, $key, $iv, false);
        $this->assertNotEquals($encrypt, $encrypt64);
        $this->assertEquals($encrypt64, base64_encode($encrypt));

    }

    /**
     * @test
     */
    public function testIv()
    {
        $cipher = 'aes-256-cbc';
        $crypt = new OpenSSL($cipher);
        $ivSize = openssl_cipher_iv_length($cipher);
        $this->assertSame($ivSize, $crypt->getIvSize());
        $iv = $crypt->createIv();
        $this->assertEquals($ivSize, strlen($iv));
    }

    /**
     * @test
     */
    public function testAvailableCiphers()
    {
        $ciphers = openssl_get_cipher_methods();
        $crypt = new OpenSSL();
        $this->assertSame($ciphers, $crypt->getAvailableCiphers());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidCipherNotAllowed()
    {
        $crypt = new OpenSSL('test');
    }
}
