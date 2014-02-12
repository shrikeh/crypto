<?php

namespace spec\Shrikeh\Crypto;

use \PhpSpec\ObjectBehavior;
use \Prophecy\Argument;
use \Shrikeh\Crypto\Password;

class PasswordSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('Shrikeh\Crypto\Password');
    }

    function it_creates_a_new_password()
    {
        $password = 'foobarbaz';

        $this->hash($password)->shouldBeValidHashOf($password);
    }

    function it_gives_me_info_on_a_hash()
    {
        $hash = password_hash('foo', PASSWORD_BCRYPT, array('cost' => 15));
        $info = password_get_info($hash);
        $this->getInfo($hash)->shouldReturn($info);
    }

    function it_returns_true_when_verifying_a_valid_hash()
    {
        $password = 'foobarbaz';
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $this->verify($password, $hash)->shouldReturn(true);
    }

    function it_returns_false_when_verifying_an_invalid_hash()
    {
        $password = 'foobarbaz';
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $this->verify('barbazbop', $hash)->shouldReturn(false);
    }

    function it_returns_true_when_a_password_generated_with_different_algorithm_to_specified_needs_rehashing()
    {
        $hash = password_hash('foobarbaz', PASSWORD_BCRYPT);
        $this->needsRehash($hash, PASSWORD_DEFAULT)->shouldReturn(true);
    }

    function it_returns_true_when_a_password_generated_with_different_cost_to_specified_needs_rehashing()
    {
        $hash = password_hash('foobarbaz', PASSWORD_DEFAULT, array('cost' => 6));
        $this->needsRehash($hash, PASSWORD_DEFAULT)->shouldReturn(true);
    }

    function it_returns_false_when_a_password_doesnt_need_rehashing()
    {
        $hash = password_hash('foobarbaz', PASSWORD_DEFAULT, array('cost' => Password::DEFAULT_COST));
        $this->needsRehash($hash, PASSWORD_DEFAULT)->shouldReturn(false);
    }

    public function getMatchers()
    {
        return array(
          'beValidHashOf'  => function($hash, $password) {
               return password_verify($password, $hash);
          }
        );
    }
}
