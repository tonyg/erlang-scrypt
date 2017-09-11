# erlscrypt: Port driver for Colin Percival's "scrypt" function

[scrypt](http://www.tarsnap.com/scrypt.html), a Password-Based Key
Derivation Function from Colin Percival, from [version
1.1.6](http://www.tarsnap.com/scrypt/scrypt-1.1.6.tgz) of his library.

For general background on what `scrypt` is, and why it's useful, see
[these slides (PDF)](http://www.tarsnap.com/scrypt/scrypt-slides.pdf)
and [Colin Percival's page on
scrypt](http://www.tarsnap.com/scrypt.html).

## Using the library

The entry points are `erlscrypt:scrypt/6` and `erlscrypt:scrypt/7`.

## erlscrypt:scrypt([nif], Passwd, Salt, N, R, P, Buflen)

Atom `nif` can be passed as optional first parameter to gain some marginal speed over
port.

Both `Passwd` and `Salt` must be binaries. `N`, `R`, and `P` control
the complexity of the password-derivation process. `Buflen` is the
number of bytes of key material to generate.

For some good choices for `N`, `R` and `P`, see [the
paper](http://www.tarsnap.com/scrypt/scrypt.pdf).

Example:

    1> erlscrypt:scrypt(<<"pleaseletmein">>, <<"SodiumChloride">>, 16384, 8, 1, 64).
    <<112,35,189,203,58,253,115,72,70,28,6,205,129,253,56,235,
      253,168,251,186,144,79,142,62,169,181,67,246,84,...>>
    2> erlscrypt:scrypt(nif,<<"pleaseletmein">>, <<"SodiumChloride">>, 16384, 8, 1, 64).
    <<112,35,189,203,58,253,115,72,70,28,6,205,129,253,56,235,
      253,168,251,186,144,79,142,62,169,181,67,246,84,...>>

## License
Please see LICENSE for more details
