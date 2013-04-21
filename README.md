# erlang-scrypt: Port driver for Colin Percival's "scrypt" function

[scrypt](http://www.tarsnap.com/scrypt.html), a Password-Based Key
Derivation Function from Colin Percival, from [version
1.1.6](http://www.tarsnap.com/scrypt/scrypt-1.1.6.tgz) of his library.

For general background on what `scrypt` is, and why it's useful, see
[these slides (PDF)](http://www.tarsnap.com/scrypt/scrypt-slides.pdf)
and [Colin Percival's page on
scrypt](http://www.tarsnap.com/scrypt.html).

## Depending on this library from rebar

Include it as a dep:

    {deps_dir, ["deps"]}.
    {deps,
     [
      ...
      {scrypt, "1.1.6:0",
       {git, "git://github.com/tonyg/erlang-scrypt.git", "master"}}
     ]}.

## Using the library

Include it in your application's `applications` key in its `.app` file:

    {application, your_app,
     [
      {applications, [
                      ...
                      scrypt
                     ]},
      ...
     ]}.

The only entry point is `scrypt:scrypt/6`.

## scrypt:scrypt(Passwd, Salt, N, R, P, Buflen)

Both `Passwd` and `Salt` must be binaries. `N`, `R`, and `P` control
the complexity of the password-derivation process. `Buflen` is the
number of bytes of key material to generate.

For some good choices for `N`, `R` and `P`, see [the
paper](http://www.tarsnap.com/scrypt/scrypt.pdf).

Example:

    Eshell V5.9.1  (abort with ^G)
    1> scrypt:scrypt(<<"pleaseletmein">>, <<"SodiumChloride">>, 16384, 8, 1, 64).
    <<112,35,189,203,58,253,115,72,70,28,6,205,129,253,56,235,
      253,168,251,186,144,79,142,62,169,181,67,246,84,...>>

## License

erlang-scrypt is written by Tony Garnock-Jones
<tonygarnockjones@gmail.com> and is licensed under the [2-clause BSD
license](http://opensource.org/licenses/BSD-2-Clause):

> Copyright &copy; 2013, Tony Garnock-Jones  
> All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions
> are met:
>
> 1. Redistributions of source code must retain the above copyright
>    notice, this list of conditions and the following disclaimer.
>
> 2. Redistributions in binary form must reproduce the above copyright
>    notice, this list of conditions and the following disclaimer in
>    the documentation and/or other materials provided with the
>    distribution.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
> "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
> LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
> FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
> COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
> INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
> BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
> LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
> CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
> LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
> ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
> POSSIBILITY OF SUCH DAMAGE.

erlang-scrypt relies on `scrypt` itself, which is written by Colin
Percival and licensed as follows:

> Copyright 2009 Colin Percival  
> All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions
> are met:
>
> 1. Redistributions of source code must retain the above copyright
>    notice, this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright
>    notice, this list of conditions and the following disclaimer in the
>    documentation and/or other materials provided with the distribution.
>
> THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
> ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
> IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
> ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
> FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
> DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
> OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
> HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
> LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
> OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
> SUCH DAMAGE.
