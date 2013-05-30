<?php
namespace ShrikehTests\Crypto;

use \PHPUnit_Framework_TestCase as TestCase;
use \Pimple;

abstract class TestAbstract extends TestCase
{

    /**
     * The service container.
     *
     * @var \Pimple;
     */
    protected $container;

    public function setup()
    {
        $container = new Pimple();
    }
}
