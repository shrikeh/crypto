<?php
/**
 * Created by PhpStorm.
 * User: bhanlon
 * Date: 12/02/2014
 * Time: 16:05
 */

namespace Shrikeh\Crypto\Password\Encoder;

use \ArrayAccess;
use Shrikeh\Crypto\Password\Encoder as EncoderInterface;

final class HashEncoder implements EncoderInterface
{
    private $algo;

    private $options;

    public static function fromInfo(array $info)
    {
        return new self(
            $info[self::INFO_ALGO],
            $info[self::INFO_OPTIONS]
        );
    }

    public static function fromHash($hash)
    {
        return self::fromInfo(password_get_info($hash));
    }

    public static function bcrypt(array $options = array())
    {
        return new self(PASSWORD_BCRYPT, $options);
    }

    public static function default()
    {
        return new self(PASSWORD_DEFAULT);
    }

    private function __construct(
        $algo = PASSWORD_DEFAULT,
        array $options = array()
    ) {
        $this->algo     = $algo;
        $this->bcryptOptions($options);
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
        return password_hash(
            $password,
            $this->algo(),
            $this->options()
        );
    }

    public function needsRehash($hash)
    {
      return password_needs_rehash(
          $hash,
          $this->algo(),
          $this->options()
      );
    }

    private function bcryptOptions($options)
    {
        foreach ($options as $key => $value) {
            switch ($key) {
              case self::OPTIONS_SALT:
                  break;
              case self::OPTIONS_COST:
                  if (!is_numeric($value)) {
                    $msg = 'Cost must be numeric bust received %s';
                    throw new \InvalidArgumentException(
                        sprintf($msg, $value)
                    );
                  }
                  break;
              default:
                  $msg = 'Unknown key %s in password options';
                  throw new \InvalidArgumentException(sprintf($msg, $key));
            }
        }
        $this->options = $options;
    }
}
