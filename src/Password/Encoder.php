<?php

namespace Shrikeh\Crypto\Password;

use Shrikeh\Crypto\Password\Hash;

interface Encoder
{
    const INFO_ALGO = 'algo';

    const INFO_OPTIONS = 'options';

    const OPTIONS_COST = 'cost';

    const OPTIONS_SALT = 'salt';

    public function algo();

    public function hash($password);

    public function needsRehash($hash);
}
