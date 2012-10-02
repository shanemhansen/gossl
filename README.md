gossl is a go library for interfacing with the venerable
openssl library. It currently provides a dropin replacement for:
crypto/sha512
crypto/sha256
crypto/sha
crypto/aes (the aes 128, 192, and 256 ECB mode ciphers)
crypto/tls.{Listener,LoadX509KeyPair}

Also included are a couple example command line utilities for hashing files and strings.
They should run as fast as an equivalant c program (sha256sum). All of the openssl
context api functions there. A new BIO has been created that allows OpenSSL to treat
a go net.Conn the same way it would treat a raw socket connection, pretty neat!

Instructions
============

Make sure you have libssl-dev and libssl1.0.0 installed on your system.
This is needed to link against openssl.
This is a standard go package, so you should be able to just:

    go install github.com/shanemhansen/gossl/examples/hashfile githum.com/shanemhansen/gossl/examples/hashstring

    hashfile /etc/hosts
    hashstring 'something'

    go install github.com/shanemhansen/testhttpserver
    
    testhttpserver -cert $somecert -key $somekey


Rationale
=========

You might ask, "why create another crypto library?".

* OpenSSL is a well audited and tested codebase.
* Performance
* Access to existing plugins/engines (cryptodev, gmp, af_alg)
* More options for parsing exotic certificates and keys (including passphrase protected)
* More ciphers and digests supported
* OpenSSL provides more hooks (that we don't yet expose) for fine grained control of validation.
* All TLS/SSL versions supported. (DTLS support coming soon)
* Works better with buggy clients/servers. (For example ab chokes on crypto/tls based servers)

Unrationale
===========

* Requires CGO
* Nowhere as elegant as crypto/tls
* crypto/tls will probably catch up in terms of features and performance


Roadmap
=======

Expose the complete OpenSSL api as well as making interoperability
between crypto/tls and gossl possible. For example, you can use
gossl to parse keys and certificates that crypto/tls can't handle yet.
Connections are net.Conn's Listeners are net.Listener's, hashes and digests
are... well you get the point.
