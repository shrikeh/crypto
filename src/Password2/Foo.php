<?php

namespace Shrikeh\Crypto\Password;

final class Foo
{
    private $hash;

    public static function hash($password, Encoding $encoding)
    {
        return new self($hash);
    }

    private function __construct($hash)
    {
        $this->hash = $hash;
    }
}
