ssl is a 100% incomplete go library for interfacing with the venerable
openssl library. It currently provides a dropin replacement for:
crypto/sha512
crypto/sha256
crypto/sha

Also included are a couple example command line utilities for hashing files and strings.
They should run as fast as an equivalant c program (sha256sum).

Rationale
=========

You might ask, "why create another crypto library?". OpenSSL is well tested,
well optimized code base. Benchmarks on my quad core i7 laptop show sha256
to be about 5x faster using OpenSSL. Also, OpenSSL has hardware acceleration
features (that aren't enabled yet) which would allow a go program to have
hardware accelerated crypto. In my case, I run on a low power arm chip,
so being able to transparently offload crypto to a dedicated crypto chip
is a big win.

Roadmap
=======

Whatever I have time to do. I'd like to create a set of dropin replacements
for the go crypto/* packages. Also, I want to enable support for ssl on
go sockets, so go programs can take advantage of the performance of OpenSSL.

instructions
============

Make sure you have libssl-dev and libssl1.0.0 installed on your system.
This is needed to link against openssl.
This is a standard go package, so you should be able to just:
go install ssl hashfile hashstring

hashfile /etc/hosts
hashstring 'something'
