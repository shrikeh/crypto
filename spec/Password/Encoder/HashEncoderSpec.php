<?php

namespace spec\Shrikeh\Crypto\Password\Encoder;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

use Shrikeh\Crypto\Password\Encoder;

class HashEncoderSpec extends ObjectBehavior
{
    function it_is_an_encoder()
    {
        $this->shouldHaveType('Shrikeh\Crypto\Password\Encoder');
    }

    function it_throws_an_exception_with_unknown_options()
    {
        $options = array(
          'foo' => 'bar',
          'cost' => 10
        );
        $this->beConstructedThroughBcrypt($options);
        $this->shouldThrow('\InvalidArgumentException')->duringInstantiation();
    }

    function it_throws_an_exception_with_invalid_options()
    {
        $options = array(
          Encoder::OPTIONS_COST => 'baz'
        );
        $this->beConstructedThroughBcrypt($options);
        $this->shouldThrow('\InvalidArgumentException')->duringInstantiation();
    }

    function it_returns_the_algorithm()
    {
        $this->beConstructedThroughBcrypt();
        $this->algo()->shouldReturn(PASSWORD_BCRYPT);
    }

    function it_returns_the_options()
    {
        $options = [Encoder::OPTIONS_COST => 12];
        $this->beConstructedThroughBcrypt($options);
        $this->options()->shouldReturn($options);
    }

    function it_returns_a_hash_from_a_password()
    {
        $password = 'foobar';
        $this->beConstructedThroughDefault();
        $this->hash($password)->shouldReturnAValidHash($password);
    }

    function it_can_be_created_from_a_hash()
    {
        $options = [
          Encoder::OPTIONS_COST => 13
        ];
        $hash = password_hash(
            'bibble',
            PASSWORD_BCRYPT,
            $options
        );
        $this->beConstructedThroughFromHash($hash);
        $this->algo()->shouldReturn(PASSWORD_BCRYPT);
        $this->options()->shouldReturn($options);
    }

    function it_can_be_created_through_info()
    {
        $options = [
          Encoder::OPTIONS_COST => 13,
          Encoder::OPTIONS_SALT => 'wibble',
        ];
        $info = [
            Encoder::INFO_ALGO => PASSWORD_BCRYPT,
            Encoder::INFO_OPTIONS => $options,
        ];
      $this->beConstructedThroughFromInfo($info);
      $this->options()->shouldReturn($options);
    }

    function it_returns_a_bcrypt_encoding_through_named_constructor()
    {
        $this->beConstructedThroughBcrypt();
        $this->algo()->shouldReturn(PASSWORD_BCRYPT);
    }

    function it_returns_a_default_encoding_through_named_constructor()
    {
        $this->beConstructedThroughDefault();
        $this->algo()->shouldReturn(PASSWORD_DEFAULT);
    }

    public function getMatchers()
    {
         return [
             'returnAValidHash' => function ($hash, $password) {
                 return password_verify($password, $hash);
             },
         ];
     }
}
