# TOTP-CLI

simple authenticator for handling totp 2FA. it is currently capable of handling otpauth urls, google authenticator defaults, and manually entering in the details by hand. you have the option of using unencrypted json or yaml and can use an encrypted option that will use ChaCha20Poly1305 to secure data.

use is more geared towards development work since you are able to view and edit all information about saved records but can be used outside of that if desired.

this is only a cli application and does not communicate with outside systems. all data will be saved to the machine that it is working on.

## Usage

all commands and options can be listed by running this command:

```shell
$ totp-cli help
```

to view options and information about individual operations you can run:

```shell
$ totp-cli help [operation]
```

## Build

currently only built and tested on Ubuntu 22.04. dont expect any major issues if building on other systems but has not been formally tested.

built with Rust 1.65.0. it is using newer features so older versions are not suppored without making changes.
