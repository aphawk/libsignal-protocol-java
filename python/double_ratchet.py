# GENERATE_DH(): returns a new diffie-hellman key pair

# DH(dh_pair, dh_pub): returns the output from the Diffie-Hellman calculation between the private key from the
# DH key pair dh_pair and the DH public key dh_pub. If the DH function rejects invalid public keys,
# then this function may raise an exception which terminates processing.

# DKF_RK(rk, dh_out): returns a pair (32-byte root key, 32-byte chain key) as the output of applying a KDF keyed
# by a 32-byte root key rk to a Diffie-Hellman output dh_out.

# KDF_CK(ck:) returns a pair (32-byte chain key, 32-byte message key) as the output of applying a KDF keyed by
# a 32-byte chain key ck to some constant.

# ENCRYPT(mk, plaintext, associated_data): returns an AEAD encryption of plaintext with messae key mk.
# The associated_data is authenticated but is not included in the ciphertext. Because each message key is only used once.
# the AEAD nonce may handled in several ways: fixed to a constant; derived from mk alongside an independent AEAD encryption
# key; derived as an additional output form KDF_CK(); or chosen randomly and transmitted.

# DECRYPT(mk, ciphertext, associated_data): returns the AEAD decryption of cihpertext with message key mk. If authentication
# fails, an exception will be raised that terminates processing.


# HEADER(dh_pair, pn, n): creates a new message header containing the DH ratchet public key from the key pair in dh_pair,
# the previous chain length pn, and message number n. The returned header object contains ratchet public key dh and integers
# pn and n.

# CONCAT(ad, header): encodes a message header into a parseable byte sequence, prepends
# the ad byte sequence, and returns the result. If ad is not guaranteed to be parseable byte
# sequence , length value should be prepended to the output to ensure that the output is parseable
# as a unique pair(ad,header)

# MAX_SKIP constant also needs to be defined. THis specifies the maximum number of message
# keys that can be skipped in a single chain. It should be set high enough to tolerate routine
# lost or delayed messages, but low enough that a malicious sender can't trigger excessive
# recipient computation.



## State Variables
## DHs: DH Ratchet key pain (the "sending" or "self" ratchet key)
## DHr: DH Ratchet public key (the "received" or "remote" key)
## RK: 32-byte root key
## CKs, CKr: 32-byte Chain keys for sending and receiving
## Ns, Nr: message numbers for sending and receiving
## PN: number of messages in previous sending chain
## MKSKIPPED: dictionary of skipped-over message keys, indexed by ratchet public key and
## message number. Raises an exception if too many elements are stored.

### Initialization:
### Prior to initialization both parties must use some key agreement protocol to agree on
### agree on a 32-byte shared secret key SK and Bob's ratchet public key. These values
### will be used to populate Alice's sending chain key and Bob's root key.
### Bob's chain keys and Alice's receiving chain key will be left empty, since they
### are populated by each party's first DH ratchet step.

### (This assumes Alice begins sending messages first, and Bob does not send messages
### until he has received one of Alice's mesasges. To allow Bob to send messages
### immediately after initialization Bob's sending chain key and Alice's receiving
### chain key could be initialized to a shared secret. For the sake of simplicity we
### wont consider this further. )



### Once Alice and Bob have agreed on SK and Bob's ratchet public key, Alice calls
### RatchetInitAlice() and Bob calls RatchetInitBob():


def generate_DH():
    return 1,2

def KDF_RK(sk, dh_pair):
    return 1,2

def DH(key1,key2):
    return key1


def RatchetInitAlice(state, SK, bob_dh_public_key):
    state.DHs = generate_DH()
    state.DHr = bob_dh_public_key
    state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}


def RatchetmInitBob(state, SK, bob_dh_key_pair):
    state.DHs = bob_dh_key_pair
    state.DHr = None
    state.RK = SK
    state.CKs = None
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}


### Encrypting messages
### RatchetEncrypt() is called to encrypt messages. This function performs a
### symmetric ratchet step, then encrypts the message with resulting mesasge key.
### In addition to the message's plaintext it takes an AD byte sequence which is
### prepended to the header to form the associated data for the underlying AEAD
### encryption.:

def RatchetEncrypt(state, plaintext, AD):
    state.CKs, mk = KDF_CK(state.CKs)
    header = HEADER(state.DHs, state.PN, state.Ns)
    state.Ns += 1
    return header, ENCRYPT(mk, plaintext, CONCAT(AD,header))

### decrypting messages:
### RatchetDecrypt() is called to decrypt mesasges. This function does the following.
### * if the mesasge corresponds to a skipped message key this function decrypts the
###   message, deletes the message key, and returns

### * otherwise, if a new ratchet key has been received this function stores any
###   skipped message keys from the receiving chain and performs a DH ratchet step
###   to replace the sending and receiving chains.

### * this function then stores any skipped message keys from the current receiving
###   chain, performs a symmetric-key ratchet step to devire the relevant message key
###   and next chain key, and decrypts the message.

### If an exception is raised , then the message is discarded and changes to the state
### object are discarded. Otherwise, the decrypted plaintext is accepted and changes
### to the state object are stored.

def RatchetDecrypt(state,header,ciphertext, AD):
    plaintext= TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext != None:
        return plaintext
    if header.dh != state.DHr:
        SkipMessageKeys(state, header.pn)
        DHRatchet(state,header)
    SkipMessageKeys(state,header.n)
    state.CKr, mk = KDF_CK(state.CKr)
    state.Nr += 1

def TrySkippedMessageKeys(state, header, ciphertext, AD):
    if (header.dh, header.n) in state.MKSKIPPED:
        mk = state.MKSKIPPED[header.dh, header.n]
        del state.MKSKIPPED[header.dh, header.n]
        return DECRYPT(mk, ciphertext, CONCAT(AD,header))
    else:
        return None

def SkipMessageKeys(state, until):
    if state.Nr + MAX_SKIP < until:
        raise Error()
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = KDF_CK(state.CKr)
            state.MKSKIPPED[state.DHr,state.Nr] = mk
            state.Nr += 1

def DHRatchet(state, header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs,state.DHr))
    state.DHs = generate_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs,state.DHr))




### Recommended cryptographic algorithms
### generate_dh(): this function is recommended to generate a key pair based on the Curve25519, Curve448

### DH(dh_pair, dh_pub): this function is recommended to return the output from the x25519 or x448 function
### as defined in. There is no need to check for invalid public keys


### KDF_RK(rk, dh_out): this function
### HKDF with SHA-256, SHA-512, using rk as HKDF salt, dh_out as HKDF input key material
### and an application-specific byte sequence as HKDF info. The info value should be chosen to be distinct
### from other uses of HKDF in the application.

### KDF_CK(ck): HMAC with SHA-256 or SHA-512 is recommended, using ck as the HMAC key and using separate
### constant as input (a single byte 0x01 as input to produce the message key, and a single byte 0x02 as input
### as input to produce the next chain key)


### ENCRYPT(mk, plaintext, associated_data): this function is recommended to be implemented with an AEAD encryption scheme
### based on either SIV or a composition of CBC with HMAC. These schemes provide some misuse-resistance in case a key is
### mistakenly