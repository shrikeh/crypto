crypto
======

OOP implementations of various encryption methods for PHP. Standardises implementation across different methods (mcrypt, openssl, etc).

[![Build Status](https://travis-ci.org/shrikeh/crypto.png?branch=master)](https://travis-ci.org/shrikeh/crypto)
[![Scrutinizer Quality Score](https://scrutinizer-ci.com/g/shrikeh/crypto/badges/quality-score.png?s=39bb83c56ab01ae92b9ee4c33b371258203d734f)](https://scrutinizer-ci.com/g/shrikeh/crypto/)
[![Dependency Status](https://www.versioneye.com/user/projects/5314eb39ec1375cd39000041/badge.png)](https://www.versioneye.com/user/projects/5314eb39ec1375cd39000041)
[![Latest Stable Version](https://poser.pugx.org/shrikeh/crypto/v/stable.png)](https://packagist.org/packages/shrikeh/crypto)
[![Total Downloads](https://poser.pugx.org/shrikeh/crypto/downloads.png)](https://packagist.org/packages/shrikeh/crypto)
[![Latest Unstable Version](https://poser.pugx.org/shrikeh/crypto/v/unstable.png)](https://packagist.org/packages/shrikeh/crypto)
[![License](https://poser.pugx.org/shrikeh/crypto/license.png)](https://packagist.org/packages/shrikeh/crypto)

## Why bother?

There's a few advantages to handling encryption and password hashing via objects.

* if you use PHPUnit or Mockery, you'll find it a lot easier to mock pass/fail results.
* all of these have tests, so you don't have to write any for basic encryption, simplifying development.
* it helps dependency injection-led development by abstracting away the details of encryption implementation
* swapping out one form of encryption for another should be fairly easy (so long as you also update your data)

## The Dos and Don'ts of Passwords

* don't use the username of a user as these aren't globally unique and allow for rainbow table attacks.



