<?php
namespace ShrikehTests\Crypto\Encryption;

use \stdClass;

use \PHPUnit_Framework_TestCase as TestCase;
use \Shrikeh\Crypto\Encryption\Mcrypt;

class McryptTest extends TestCase
{
    /**
     * @test
     */
    public function testCrypt()
    {
        $cipher = MCRYPT_RIJNDAEL_128;
        $crypt = new Mcrypt($cipher);

        $this->assertSame($cipher, $crypt->getCipher());

        $ivSize = mcrypt_get_iv_size($cipher, MCRYPT_MODE_CBC);
        $iv = mcrypt_create_iv($ivSize, MCRYPT_RAND);
        $data = new stdClass();

        $data->foo = 'bar';
        $key = 'wibble';

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
        $crypt = new Mcrypt(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $ivSize = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $this->assertSame($ivSize, $crypt->getIvSize());
        $iv = $crypt->createIv();
        $this->assertEquals($ivSize, strlen($iv));
    }

    /**
     * @test
     */
    public function testAvailableCiphers()
    {
        $ciphers = mcrypt_list_algorithms();
        $crypt = new Mcrypt(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $this->assertSame($ciphers, $crypt->getAvailableCiphers());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidCipherNotAllowed()
    {
        $crypt = new Mcrypt('test');
    }
}
