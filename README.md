crypto
======

OOP implementations of various encryption methods for PHP. Standardises implementation across different methods (mcrypt, openssl, etc).

[![Total Downloads](https://poser.pugx.org/shrikeh/crypto/downloads.png)](https://packagist.org/packages/shrikeh/crypto)

## Why bother?

There's a few advantages to handling encryption and password hashing via objects.

* if you use PHPUnit or Mockery, you'll find it a lot easier to mock pass/fail results.
* all of these have tests, so you don't have to write any for basic encryption, simplifying development.
* it helps dependency injection-led development by abstracting away the details of encryption implementation
* swapping out one form of encryption for another should be fairly easy (so long as you also update your data)



