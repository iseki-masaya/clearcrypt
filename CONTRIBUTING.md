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

1. Secret strings MUST be compared in constant time
2. Programs MUST NOT branch on secret data
3. Secret data MUST NOT be used for table lookups
4. Loops MUST NOT be bounded secret-dependent values
5. Compiler optimizations which might impact security SHOULD be worked around
6. Potentially insecure APIs MUST be clearly labeled so they're never confused
   with secure ones
7. The abstraction levels of the library SHOULD be cleanly separated
8. Unsigned bytes MUST always be used to represent binary data
9. Separate types MUST be used for secret and non-secret data
10. Separate types MUST always be used for different types of information
11. Memory MUST always be cleaned after use
12. Random data MUST always come from a secure source

## Style

Please follow the [Rust style guide].

[Rust style guide]: https://github.com/mozilla/rust/wiki/Note-style-guide

## Include a test

All pull requests containing code should include tests. These tests should
take the form of a [#[test]](http://static.rust-lang.org/doc/master/guide-testing.html)
attribute, and test the relevant functionality to be added.

## Submitting a patch

* Fork this repository on github
* Make your changes and send us a pull request
* Your change will be discussed for potential inclusion
