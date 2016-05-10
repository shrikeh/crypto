<?php
/**
 * Created by PhpStorm.
 * User: bhanlon
 * Date: 12/02/2014
 * Time: 16:05
 */

namespace Shrikeh\Crypto\Password;

use Shrikeh\Crypto\Password;
use Shrikeh\Crypto\Password\Encoder;
use Shrikeh\Crypto\Password\Encoder\HashEncoder;



class Hash implements Password
{
    private $hash;

    public static function create($password, Encoder $encoder)
    {
        return new self($encoder->hash($password));
    }

    public function __construct($hash)
    {
        $this->hash = $hash;
    }

    public function info()
    {
        return HashEncoder::fromHash($this->hash);
    }

    public function verify($password)
    {
        return password_verify($password, $this->hash);
    }

    public function needsRehash(Encoder $encoder)
    {
        return $encoder->needsRehash($this->hash);
    }
}
