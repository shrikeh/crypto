<?php

namespace Shrikeh\Crypto\Password\Hash;

interface Encoding
{
    public function algo();

    public function options();
}
