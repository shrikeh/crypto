<?php
/**
 * Created by PhpStorm.
 * User: bhanlon
 * Date: 12/02/2014
 * Time: 16:05
 */

namespace Shrikeh\Crypto\Password\Hash\Encoding;

use Shrikeh\Crypto\Password\Hash\Encoding;

final class PasswordHash implements Encoding
{
    private $algo;

    private $options;

    public function __construct(
        $algo = PASSWORD_DEFAULT,
        array $options = array()
    ) {
        $this->algo = $algo;
        $this->options = $options;
    }

    public function algo()
    {
        return $this->algo;
    }

    public function options()
    {
        return $this->options;
    }

    public function hash($password)
    {
        $hash = password_hash(
            $password,
            $this->algo,
            $this->options
        );
        return new Hash($hash);
    }

    public function needsRehash(Hash $hash)
    {
        return $hash->needsRehash($this);
    }
}
