<?php
/**
 * Created by PhpStorm.
 * User: bhanlon
 * Date: 12/02/2014
 * Time: 16:05
 */

namespace Shrikeh\Crypto;

use Shrikeh\Crypto\Password\Encoder;

interface Password
{

    public function verify($password);

    public function info();

    public function needsRehash(Encoder $encoder);
}
