<?php
/**
 * Created by PhpStorm.
 * User: bhanlon
 * Date: 12/02/2014
 * Time: 16:05
 */

namespace Shrikeh\Crypto\Password\Hash\Encoding;

use Shrikeh\Crypto\Password\Hash\Encoding;

final class Bcrypt implements Encoding
{
    private $options;

    public function __construct(array $options = array())
    {
        $this->options = $options;
    }

    public function algo()
    {
        return PASSWORD_BCRYPT;
    }

    public function options()
    {
        return $this->options;
    }

    public function hash($password)
    {
        $hash = password_hash(
            $password,
            PASSWORD_BCRYPT,
            $this->options
        );
        return new Hash($hash);
    }

    public function needsRehash(Hash $hash)
    {
        return $hash->needsRehash($this);
    }
}
