# Preface

The goal is to create a minimal libsodium module for micropython that exposes
just enough for Ed25519 signatures and possibly Curve25519 ECDHE. This involves
writing micropython runtime wrappers for everything. Below are documented the
bindings for useful PyNaCl features.


# PyNaCl bindings

## SigningKey (Ed25519)

nacl.bindings.crypto_sign_SEEDBYTES = crypto_sign_secretkeybytes() // 2

### nacl.bindings.crypto_sign_seed_keypair()

= crypto_sign_seed_keypair()
crypto_sign_PUBLICKEYBYTES = crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = crypto_sign_secretkeybytes()

### nacl.bindings.crypto_sign()

= crypto_sign()

nacl.bindings.crypto_sign_BYTES = crypto_sign_bytes()

### nacl.bindings.crypto_sign_ed25519_sk_to_curve25519()

= crypto_sign_ed25519_sk_to_curve25519()
crypto_sign_PUBLICKEYBYTES = crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = crypto_sign_secretkeybytes()

## VerifyKey (Ed25519)

### nacl.bindings.crypto_sign_open()

= crypto_sign_open()


## PrivateKey (X25519)

nacl.bindings.crypto_box_SECRETKEYBYTES = crypto_box_secretkeybytes()
nacl.bindings.crypto_box_SEEDBYTES = crypto_box_seedbytes()

### nacl.bindings.crypto_scalarmult_base()

= crypto_scalarmult_base()
crypto_scalarmult_BYTES = crypto_scalarmult_bytes()

## nacl.bindings.crypto_box_seed_keypair()

= crypto_box_seed_keypair()
crypto_box_PUBLICKEYBYTES = crypto_box_publickeybytes()
crypto_box_SECRETKEYBYTES = crypto_box_secretkeybytes()

## PublicKey (X25519)

crypto_box_PUBLICKEYBYTES = crypto_box_publickeybytes()
crypto_box_SECRETKEYBYTES = crypto_box_secretkeybytes()

## Box (X25519)

nacl.bindings.crypto_box_NONCEBYTES = crypto_box_noncebytes()

### nacl.bindings.crypto_box_beforenm()

= crypto_box_beforenm()

### nacl.bindings.crypto_box_afternm()

= crypto_box_afternm()
crypto_box_BEFORENMBYTES = crypto_box_noncebytes()
crypto_box_ZEROBYTES = crypto_box_zerobytes()

### nacl.bindings.crypto_box_open_afternm()

= crypto_box_open_afternm()




