<?php
/**
 * Created by PhpStorm.
 * User: bhanlon
 * Date: 12/02/2014
 * Time: 16:05
 */

namespace Shrikeh\Crypto\Password\Hash;

use Shrikeh\Crypto\Password;
use Shrikeh\Crypto\Password\Hash;
use Shrikeh\Crypto\Password\Hash\Encoding;

final class PasswordHash implements Hash, Password
{
    private $hash;

    public static function create($password, Encoding $options)
    {
        $hash = password_hash(
            $password,
            $options->algo(),
            $options->options()
        );
        return new self($hash);
    }

    private function __construct($hash)
    {
        $this->hash = $hash;
    }

    public function __toString()
    {
        return $this->hash;
    }

    public function needsRehash(Encoding $options)
    {
      return password_needs_rehash(
          $this->hash,
          $options->algo(),
          $options->options()
      );
    }


}
