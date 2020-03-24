# Linux API for Kryptor (HSM on a chip)

This is a testing and demo application for the Kryptor Hardware Security Module running ona FPGA Intel MAX10. The application is built for Raspberry Pi, using SPI interface to talk to the chip.

It's an initial state of the demo, so the protocol implementation part isn't fully abstracted yet from the underlying os/system/hw. The typical function implementation is done in two parts - fairly abstract request serialization function, and the function calling linux-specific SPI transfer functions. 

The HSM chip has a hardware blocks for cryptographic primitives, and a mix of volatile and non-volatile storages for the keys and small blocks of user data. The required high-level funtionality is achieved by manipulating the chip's state, generally in multiple transactions. Only the message-oriented api is released at the moment.

## The list of available cryptographic primitives
1. FIGARO TRNG
2. Curve25519 ECDH
3. Skein-256 hash
4. Camellia-128 block cipher

# Getting Started

Connect the HSM board to Raspberry Pi's SPI0 port, and powere the board either with RPi's 5v output, or with external source. Onboard regulator allows using LiPo battery, as well as 5v sources, like USB port.
Run the hsm console client app with -m option to see the chip's version and serial number, and to confirm everything is ok.
You might need to run raspi-config to enable the SPI port first.

The options supported by command line interface:
  -n --rng X     generate XXX random bytes
  -o --file filename save output to file
  -S --stdout    output results into stdout
  -s --speed X   max speed (Hz), default 2000000
  -C --ecdh X    derive shared secret from secret key X [0-3] or root key
  -k --key filename  use public key (for ECDH) or symmetric key file
  -w --with X      target symmetrical key X [0-3] in ecdh or file encryption
  -g --gen-sym  X  generate new symmetrical key X [0-3]
  -G --gen-priv X  generate new keypair X [0-3]
  -P --read-pub X  read public key from keypair X [0-3]
  -R --root-pub    read root public key
  -r --read-sym X  read symmetric key X [0-3]
  -l --load-sym x  setup symmetrical key X [0-3] using keyfile given with -k
  -e --encrypt filename  encrypt file
  -d --decrypt filename  decypt file
  -h --hash filename   hash the file
  -H --hash-size x     hash length in bytes, default 16
  -c --cbc        use cbc for encryption
  -i --iv string  use initialization vector
  -m --serial   read device serial/product ids
  -b --blink x  enable or disable the hearbeat led
  -L --leds x   set user leds status to x
  -z --erase-sym x   wipe the symmetric key x [0-3] with zeroes
  -Z --erase-priv x  wipe the private key x [0-3] with zeroes

Examples of use (in no particular order):
```
# generate new symmetrical key 0
./hsm_cli -g 0

# read the generated key 0
./hsm_cli -r 0

# load symmetrical key 1 from user file
./hsm_cli -l 1 -k keyfilename

# generate new keypair 2
./hsm_cli -G 2

# read the public key of keypair 2
./hsm_cli -P 2

# derive shared secret using private key 0 and user-supplied public key, save result into symmetrical key slot 1
./hsm_cli -C 0 -w 1 -k pub_filename

# derive shared secret using root key and user-supplied public key, save result into setting symmetrical key slot 2
./hsm_cli -C root -w 2 -k pub_filename

# encrypt file with symmetrical key 2
./hsm_cli -e plain_filename -w 2 -c -o encrypted_filename

# decrypt the file with symmetrical key 1
./hsm_cli -d encrypted_filename -w 1 -c -o decrypted_filename

# generate random numbers, specifying the output size in bytes
./hsm_cli -n 10000 -o random.bits

# hash the content of a file
./hsm_cli -h filename

# read the chip serial/product ids
./hsm_cli -m
```

## Authors
vlad@skudo.tech

## License
This project is licensed under the MIT License

## Acknowledgments

www.skudo.tech
