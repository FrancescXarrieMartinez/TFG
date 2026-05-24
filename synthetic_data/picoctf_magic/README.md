# picoCTF Magic batch (4 vulnerable variations)

This batch contains four synthetic **VULNERABLE** entries derived from the seed at `dataset.json` index 4 (`picoctf-magic`). It is the same kind of AES-128-CBC padding oracle as the Cryptopals batch, except the wire format here is hex-encoded rather than base64. All four entries are part of the main dataset.

The four variations differ in scenario (a CTF session service, an API gateway, a mobile-game save file, and a web-form CSRF check), in how the code is organised, and in the padding-check idiom. They were verified by running the reference exploit -- which recovered each plaintext -- and by the pairwise-similarity check, whose most similar pair scored 0.63, under the 0.85 limit.

One entry, `syn-03`, was **regenerated after a review**. Its first version happened to share both its code structure *and* its padding-check idiom with `syn-01`, which is exactly the kind of near-duplication we want to avoid. It was rebuilt with a different structure (a static-utility class) and a different idiom (a walrus one-liner) so that, across the batch, no pair shares both of those dimensions. That "vary at least one of structure or idiom for every pair" rule is the small methodology refinement this batch contributed.
