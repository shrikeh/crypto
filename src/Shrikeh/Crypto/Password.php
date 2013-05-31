<?php
namespace Shrikeh\Crypto;

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
    const DEFAULT_ALGORITHM = PASSWORD_BCRYPT;

    /**
     * The application-specific salt to use.
     * @var string
     */
    protected $salt;


    /**
     * Default runtime-set algorithm for encryption.
     *
     * @var integer
     */
    protected $defaultAlgorithm;

    /**
     * The runtime-set CPU cost,
     *
     * @var integer
     */
    protected $defaultCost;

    /**
     * Simple constructor.
     *
     * @param string $salt
     */
    public function __construct(
        $salt,
        $defaultAlgorithm = self::DEFAULT_ALGORITHM,
        $defaultCost = self::DEFAULT_COST
    ) {
        $this->salt             = (string) $salt;
        $this->defaultAlgorithm = $defaultAlgorithm;
        $this->defaultCost      = $defaultCost;
    }

    /**
     * Verify the user(name) and password provided.
     *
     * @param string $user
     * @param string $password
     * @param string $hash
     */
    public function verify(
        $user,
        $password,
        $hash
    ) {
        return password_verify(
            $this->getSalted($user, $password),
            $hash
        );
    }

    /**
     * Calculate if the password needs rehashing.
     * @param string $hash
     * @param integer $algorithm
     * @param integer $cost
     */
    public function needsRehash(
        $hash,
        $algorithm = null,
        $cost = null
    ) {
        if (null === $algorithm) {
            $algorithm = $this->defaultAlgorithm;
        }

        if (null === $cost) {
            $cost = $this->defaultCost;
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
     * @param string $user
     * @param string $password
     * @param int $algorithm
     * @param int $cost
     */
    public function getHash(
        $user,
        $password,
        $algorithm = null,
        $cost = null
    ) {
        if (null === $algorithm) {
            $algorithm = $this->defaultAlgorithm;
        }

        if (null === $cost) {
            $cost = $this->defaultCost;
        }
        return $this->create(
            $this->getSalted($user, $password),
            $algorithm,
            $cost
        );
    }

    /**
     * Generate the hash.
     *
     * @param string $saltedPassword
     * @param integer $algorithm
     * @param integer $cost
     */
    public function create(
        $saltedPassword,
        $algorithm,
        $cost
    ) {
        return password_hash(
            $saltedPassword,
            $algorithm,
            ['cost' => $cost]
        );
    }

    /**
     * Return the salted details.
     *
     * @param string $user
     * @param string $password
     * @return string
     */
    protected function getSalted($user, $password)
    {
        return (string) $user . $this->salt . $password;
    }
}
