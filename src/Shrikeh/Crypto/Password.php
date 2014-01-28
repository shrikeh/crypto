<?php
/**
 * Library and wrapper around password functions. Useful for mocking.
 *
 * @author Barney Hanlon <barney@shrikeh.net>
 */
namespace Shrikeh\Crypto;
/**
 * Library and wrapper around password functions. Useful for mocking.
 *
 * @author Barney Hanlon <barney@shrikeh.net>
 */
class Password
{
    /**
     * The cost (in terms of CPU) of generating a hash.
     *
     * @var integer
     */
    const DEFAULT_COST      = 13;

    /**
     * The default algorithm to use.
     *
     * @var integer
     */
    const DEFAULT_ALGORITHM = \PASSWORD_BCRYPT;

    /**
     * The application-specific pepper to use. This is a sprintf()-compatible
     * string
     * @var string
     */
    private $pepper = '%s%s';


    /**
     * Default runtime-set algorithm for encryption.
     *
     * @var integer
     */
    private $algorithm;

    /**
     * The runtime-set CPU cost,
     *
     * @var integer
     */
    private $cost;

    /**
     * Simple constructor.
     *
     * @param integer $algorithm
     * @param integer $cost
     * @param string $pepper
     */
    public function __construct(
        $algorithm = self::DEFAULT_ALGORITHM,
        $cost = self::DEFAULT_COST,
        $pepper = ''
    ) {

        $this->algorithm    = $algorithm;
        $this->cost         = $cost;
        $this->pepper       = (string) $pepper;
    }

    /**
     * Verify the user(name) and password provided.
     *
     * @param string $user
     * @param string $password
     * @param string $hash
     * @return boolean
     */
    public function verify(
        $user,
        $password,
        $hash
    ) {
        return password_verify(
            $this->getPeppered($user, $password),
            $hash
        );
    }

    /**
     * Calculate if the password needs rehashing.
     *
     * @param string $hash
     * @param integer $algorithm
     * @param integer $cost
     * @return boolean
     */
    public function needsRehash(
        $hash,
        $algorithm = null,
        $cost = null
    ) {
        if (null === $algorithm) {
            $algorithm = $this->algorithm;
        }

        if (null === $cost) {
            $cost = $this->cost;
        }
        return password_needs_rehash(
            $hash,
            $algorithm,
            ['cost' => $cost]
        );
    }

    /**
     * Get a hash of the user(name) and password.
     *
     * @param string $user The user identifier (i.e. email, username, etc)
     * @param string $password The user's password
     * @param integer $algorithm The algorithm to use
     * @param integer $cost The CPU 'cost' to use
     * @return string The hash of the username and password (and pepper if used)
     */
    public function getHash(
        $user,
        $password,
        $algorithm = null,
        $cost = null
    ) {
        if (null === $algorithm) {
            $algorithm = $this->algorithm;
        }

        if (null === $cost) {
            $cost = $this->cost;
        }
        return $this->create(
            $this->getPeppered($user, $password),
            $algorithm,
            $cost
        );
    }

    /**
     * Generate the hash.
     *
     * @param string $pepperedPassword
     * @param integer $algorithm
     * @param integer $cost The CPU cost we wish to use
     * @return string the password hash
     */
    public function create(
        $pepperedPassword,
        $algorithm,
        $cost
    ) {
        return password_hash(
            $pepperedPassword,
            $algorithm,
            ['cost' => $cost]
        );
    }

    /**
     * Return the peppered details.
     *
     * @param string $user The user identifier (i.e. email, username, etc)
     * @param string $password The user's password
     * @return string the peppered string
     */
    private function getPeppered($user, $password)
    {
        return (string) sprintf($this->pepper, $user, $password);
    }
}
