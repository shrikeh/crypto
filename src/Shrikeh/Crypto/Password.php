<?php
/**
 * Library and wrapper around password functions. Useful for mocking.
 *
 * @author Barney Hanlon <barney@shrikeh.net>
 */
namespace Shrikeh\Crypto;

use \Shrikeh\Crypto\Password\PasswordEncoder;
/**
 * Library and wrapper around password functions. Useful for mocking.
 *
 * @author Barney Hanlon <barney@shrikeh.net>
 */
class Password implements PasswordEncoder
{
    /**
     * The cost (in terms of CPU) of generating a hash.
     *
     * @var integer
     */
    const DEFAULT_COST = 13;

    /**
     * The default algorithm to use.
     *
     * @var integer
     */
    const DEFAULT_ALGORITHM = PASSWORD_BCRYPT;

    /**
     * Default runtime-set algorithm for encryption.
     *
     * @var integer
     */
    private $algorithm;

    /**
     * The runtime-set CPU cost.
     *
     * @var integer
     */
    private $cost;

    /**
     * Simple constructor.
     *
     * @param integer $algorithm
     * @param integer $cost
     */
    public function __construct(
        $algorithm = self::DEFAULT_ALGORITHM,
        $cost = self::DEFAULT_COST
    ) {
        $this->algorithm    = $algorithm;
        $this->cost         = $cost;
    }

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
    ) {
        return password_verify(
            $password,
            $hash
        );
    }

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
    ) {
        return password_needs_rehash(
            $hash,
            $algorithm,
            $this->setOptionCost($options)
        );
    }

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
    ) {
        if (null === $algorithm) {
            $algorithm = $this->algorithm;
        }

        return password_hash(
            $password,
            $algorithm,
            $this->setOptionCost($options)
        );
    }

    private function setOptionCost(array $options)
    {
        if (!array_key_exists('cost', $options)) {
            $options['cost'] = $this->cost;
        }
        return $options;
    }

    public function getInfo($hash)
    {
        return password_get_info($hash);
    }
}
