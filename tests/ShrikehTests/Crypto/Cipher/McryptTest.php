<?php
namespace ShrikehTests\Crypto\Cipher;

use \stdClass;

use \PHPUnit_Framework_TestCase as TestCase;
use \Shrikeh\Crypto\Cipher\Mcrypt;

class McryptTest extends TestCase
{
    /**
     * @test
     */
    public function testCrypt()
    {
        $algorithm = MCRYPT_RIJNDAEL_128;
        $crypt = new Mcrypt($algorithm);

        $this->assertSame($algorithm, $crypt->getAlgorithm());

        $ivSize = mcrypt_get_iv_size($algorithm, MCRYPT_MODE_CBC);
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
        $this->assertNotNull($iv);
        $this->assertEquals($ivSize, strlen($iv));
        $this->setExpectedException('\InvalidArgumentException');
        $crypt->validateIv(null);
    }

    /**
     * @test
     */
    public function testInvalidIv()
    {
        $crypt = new Mcrypt(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $this->setExpectedException('\InvalidArgumentException');
        $iv = mcrypt_create_iv($crypt->getIvSize() -1, MCRYPT_DEV_RANDOM);
        $crypt->validateIv($iv);
    }

    /**
     * @test
     */
    public function testAvailableAlgorithms()
    {
        $algorithms = mcrypt_list_algorithms();
        $crypt = new Mcrypt(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $this->assertSame($algorithms, $crypt->getAvailableAlgorithms());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidAlgorithmNotAllowed()
    {
        $crypt = new Mcrypt('test');
    }
}
