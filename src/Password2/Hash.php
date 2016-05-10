<?php
/**
 * Created by PhpStorm.
 * User: bhanlon
 * Date: 12/02/2014
 * Time: 16:05
 */

namespace Shrikeh\Crypto\Password;

use Shrikeh\Crypto\Password\Hash\Encoding;

interface Hash
{
    public function info();

    public function needsRehash(Encoding $options);
}
