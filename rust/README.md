r2ust
=====

This repository aims to be the playground to experiment
with Rust and Radare2, because it seems that it's the
only viable solution to solve all the problems we face
in r2 right now.

The transition to rust in r2 requires several steps,
so it's not gonna happen tomorrow because:

* We are not that experienced in Rust yet
* Rust is young compared to C
* C targets more platforms still
* Rust runtime libs 
* Rust requires sometimes lot of boilerplate

The modular design of r2 allows to replace any part of
the tool in other languages by plugins or just replacing
the entire module. But this have some problems:

* ABI incompatibility
* API stability

Ideally we should be able to mix C and Rust without any
problem and we want to improve on both sides, the codebase
is pretty big, so we need a transitional process to use
Rust instead of C wherever possible and gain experience.

Personally I find Rust more complicated than C, but also
find many benefits that are not available in other similar
languages, so I think that Rust fits better in r2 to replace
C than Go or Swift.

--pancake
