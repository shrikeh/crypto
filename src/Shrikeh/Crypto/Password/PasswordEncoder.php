<?php
/**
 * Created by PhpStorm.
 * User: bhanlon
 * Date: 12/02/2014
 * Time: 16:05
 */

namespace Shrikeh\Crypto\Password;

interface PasswordEncoder
{
    /**
     * Verify the password provided.
     *
     * @param string $password
     * @param string $hash
     * @return boolean
     */
    public function verify(
        $password,
        $hash
    );

    /**
     * Generate the hash.
     *
     * @param string $password
     * @param integer $algorithm
     * @param array $options
     * @return string the password hash
     */
    public function hash(
        $password,
        $algorithm = null,
        array $options = array()
    );

    /**
     * Return information about the hash.
     *
     * @param string $hash
     * @return array
     */
    public function getInfo($hash);

    /**
     * Calculate if the password needs rehashing.
     *
     * @param string $hash
     * @param integer $algorithm
     * @param array $options
     * @return boolean
     */
    public function needsRehash(
        $hash,
        $algorithm,
        array $options = array()
    );
}