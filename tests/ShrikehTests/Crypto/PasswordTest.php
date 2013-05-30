<?php
namespace ShrikehTests\Crypto;

use \PHPUnit_Framework_TestCase as TestCase;
use \Shrikeh\Crypto\Password;

class PasswordTest extends TestCase
{
    public function providerPassword()
    {
        return array(
            array(
                'barney',
                'test',
                'mrFlibble',
                '$2y$13$qTQvRiWHpjhQzzA2ilJDu.N706zDxjo3LzNc4u7H6WMy1aJtqVEnq',
                true,
            ),
            array(
                'barney',
                'test2',
                'mrFlibble',
                '$2y$13$qTQvRiWHpjhQzzA2ilJDu.N706zDxjo3LzNc4u7H6WMy1aJtqVEnq',
                false,
            ),
        );
    }


    /**
     * @test
     * @dataProvider providerPassword
     * @param string $username
     * @param string $password
     * @param string $salt
     * @param boolean $expected
     */
    public function testVerify($username, $password, $salt, $hash, $expected)
    {
        $passwordHelper = new Password($salt);

        $this->assertEquals(
            $expected,
            $passwordHelper->verify($username, $password, $hash)
        );
    }
}
