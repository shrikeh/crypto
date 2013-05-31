<?php
namespace ShrikehTests\Crypto\Cipher;

use \stdClass;

use \PHPUnit_Framework_TestCase as TestCase;
use \Shrikeh\Crypto\Cipher\OpenSSL;

class OpenSSLTest extends TestCase
{
    /**
     * @test
     */
    public function testCrypt()
    {
        $algorithm = 'aes-256-cbc';
        $crypt = new OpenSSL($algorithm);
        $this->assertSame($algorithm, $crypt->getAlgorithm());

        $data = new stdClass();
        $data->foo = 'bar';
        $key = 'wibble';
        $ivSize = openssl_cipher_iv_length($algorithm);
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
        $algorithm = 'aes-256-cbc';
        $crypt = new OpenSSL($algorithm);
        $ivSize = openssl_cipher_iv_length($algorithm);
        $this->assertSame($ivSize, $crypt->getIvSize());
        $iv = $crypt->createIv();
        $this->assertEquals($ivSize, strlen($iv));
    }

    /**
     * @test
     */
    public function testAvailableAlgorithms()
    {
        $algorithms = openssl_get_cipher_methods();
        $crypt = new OpenSSL();
        $this->assertSame($algorithms, $crypt->getAvailableAlgorithms());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidAlgorithmNotAllowed()
    {
        $crypt = new OpenSSL('test');
    }
}
