<?php
namespace ShrikehTests\Crypto;

use \PHPUnit_Framework_TestCase as TestCase;
use \Shrikeh\Crypto\Password;

class PasswordTest extends TestCase
{
    /**
     * Data Provider for tests
     *
     * @return array
     */
    public function providerPassword()
    {
        return array(
            array(
                'barney',
                Password::DEFAULT_COST,
                '$2y$13$qTQvRiWHpjhQzzA2ilJDu.N706zDxjo3LzNc4u7H6WMy1aJtqVEnq',
                true,
                false,
            ),
            array(
                'barney',
                Password::DEFAULT_COST,
                '$2y$13$qTQvRiWHpjhQzzA2ilJDu.N706zDxjo3LzNc4u7H6WMy1aJtqVEnq',
                false,
                false,
            ),
        );
    }


    /**
     * @test
     * @dataProvider providerPassword
     * @param string  $username
     * @param string  $password
     * @param string  $pepper
     * @param integer $cost
     * @param string  $hash
     * @param boolean $match
     * @param boolean $rehash
     */
    public function testVerify(
        $username,
        $password,
        $pepper,
        $cost,
        $hash,
        $match,
        $rehash
    ) {
        $passwordHelper = new Password(Password::DEFAULT_ALGORITHM, $cost, $pepper);

        $this->assertEquals(
            $match,
            $passwordHelper->verify($username, $password, $hash)
        );
    }

    /**
     * @test
     * @dataProvider providerPassword
     * @param string  $password
     * @param string  $pepper
     * @param integer $cost
     * @param string  $hash
     * @param boolean $match
     * @param boolean $rehash
     */
    public function testNeedsRehash(
        $password,
        $pepper,
        $cost,
        $hash,
        $match,
        $rehash
    ) {
        $passwordHelper = new Password(Password::DEFAULT_ALGORITHM, $cost);
        $this->assertEquals(
            $rehash,
            $passwordHelper->needsRehash($hash)
        );
    }

    /**
     * @test
     * @dataProvider providerPassword
     * @param string  $username
     * @param string  $password
     * @param string  $pepper
     * @param integer $cost
     * @param string  $hash
     * @param boolean $match
     * @param boolean $rehash
     */
    public function testGetHash(
        $username,
        $password,
        $pepper,
        $cost,
        $hash,
        $match,
        $rehash
    ) {
        $passwordHelper = new Password(Password::DEFAULT_ALGORITHM, $cost, $pepper);
        $hashedPassword = $passwordHelper->getHash($username, $password);
        $this->assertNotNull($hashedPassword);
    }
}
