<?php

namespace spec\Shrikeh\Crypto\Password;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

use Shrikeh\Crypto\Password\Encoder;

class HashSpec extends ObjectBehavior
{

    function it_is_a_password(Encoder $encoder)
    {
        $password = 'foo';
        $encoder->hash($password)->willReturn(
            password_hash(
                $password,
                PASSWORD_BCRYPT
            )
        );
        $this->beConstructedThroughCreate($password, $encoder);
        $this->shouldHaveType('Shrikeh\Crypto\Password');
    }

    function it_returns_true_if_the_password_matches_the_hash()
    {
        $password = 'foobarbaz';
        $hash = password_hash(
              $password,
              PASSWORD_BCRYPT
        );
        $this->beConstructedWith($hash);
        $this->verify($password)->shouldReturn(true);
    }

    function it_returns_false_if_the_password_does_not_match()
    {
        $password = 'bazbarfoo';
        $hash = password_hash(
              $password,
              PASSWORD_BCRYPT
        );
        $this->beConstructedWith($hash);
        $this->verify('some_other_password')->shouldReturn(false);
    }

    function it_returns_an_encoder_for_info()
    {
        $password = 'bazbarfoo';
        $hash = password_hash(
              $password,
              PASSWORD_BCRYPT
        );
        $this->beConstructedWith($hash);
        $this->info()->shouldHaveType('Shrikeh\Crypto\Password\Encoder');
    }
}
