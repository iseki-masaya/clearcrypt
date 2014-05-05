How To Contribute
=================

Before you begin writing any code, we'd strongly suggest you hop on the
[mailing list] and ask about what you'd like to contribute first. You can
also ask in the #cryptosphere channel on freenode.

Let's say you've done that, and now you know of a thing you'd like to add you
think might get accepted. How do you begin?

[mailing list]: https://groups.google.com/forum/#!forum/clearcryptocode

## Philosophy

New features must be treated with extreme scrutiny and suspicion, and rejected
unless there is a strong consensus that adding these features will benefit the
majority of the users of the protocol and see mainstream usage.

## The Twelve Commandments of Crypto Coding

The following are adapted from the [Coding Rules] on https://cryptocoding.net/:

[Coding Rules]: https://cryptocoding.net/index.php/Coding_rules

1. Thou shalt always compare secret strings in constant time
2. Thou shalt not branch on secret data
3. Thou shalt not perform table lookups indexed by secret data
4. Thou shalt not bound loops with secret-dependent values
5. Thou shalt always try to outsmart compiler optimizations which might affect
   the security of a given function
6. Thou shalt always make potentially insecure versions of an API obvious so
   it is never confused with the secure version
7. Thou shalt always diligently separate the abstraction levels of the
   library into separate layers
8. Thou shalt always use unsigned bytes to represent binary data
9. Thou shalt always use separate types for secret and non-secret data
10. Thou shalt ALWAYS use separate types for different types of information
11. Thou shalt always clean thy memory of secret data
12. Thou shalt always use strong randomness

## Include a test

All pull requests containing code should include tests. These tests should
take the form of a [#[test]](http://static.rust-lang.org/doc/master/guide-testing.html)
attribute, and test the relevant functionality to be added.

## Submitting a patch

* Fork this repository on github
* Make your changes and send us a pull request
* Your change will be discussed for potential inclusion
