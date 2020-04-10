# rdp-rs
Remote Desktop Protocol in RUST

`rdp-rs` is a pure Rust implementation of Microsoft Remote Desktop Protocol.
`rdp-rs` is delivery with an client implementation named `mstsc-rs`.

This package is main focused on security, and allows to address user who wants a safe client or security researcher that want to play with RDP.

## Why ?

Remote Desktop Protocol is a complex protocol, and it's hard to play easily with. 
I've already implemented in Python and Javascript with an event driven pattern.
It appears that this kind of pattern raise the complexity of the library, and at the end there is a lot of bugs and no PR, and nobody can't play with RDP in deeper.

On other side, there is no *secure* implementation of the RDP protocol open sourced.

At the end, I would like to build an high secure, cross platform and highly customizable client.

## Where ?

For windows platform, there is some prebuilt binaries here.

To use the `rdp-rs` library in your project, add the following to `Cargo.toml`:
```
[dependencies]
rdp-rs = "0.4"
```
 
## Play with `mstsc-rs`

`mstsc-rs` is a RDP client, based on `rdp-rs` crate. It's cross platform and highly customizable :

```
mstsc-rs 0.1.0
Sylvain Peyrefitte <citronneur@gmail.com>
Secure Remote Desktop Client in RUST

USAGE:
    mstsc-rs.exe [FLAGS] [OPTIONS]

FLAGS:
        --admin      Restricted admin mode
        --auto       AutoLogon mode in case of SSL nego
        --blank      Do not send credentials at the last CredSSP payload
        --check      Check the target SSL certificate
        --ssl        Disable Netwoek Level Authentication and only use SSL
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --dom <domain>       Windows domain [default: ]
        --hash <hash>        NTLM Hash
        --height <height>    Screen height [default: 600]
        --layout <layout>    Keyboard layout: us or fr [default: us]
        --name <name>        Name of the client send to the server [default: mstsc-rs]
        --pass <password>    Password [default: ]
        --port <port>        Destination Port [default: 3389]
        --target <target>    Target IP of the server
        --user <username>    Username [default: ]
        --width <width>      Screen width [default: 800]
```

`mstsc-rs` have been tested to connect to server ran from Windows 7 to Windows 10.

### Basic connection (using Network Level Authentication over SSL)

By default `mstsc-rs` use NLA as authentication protocol :
```
mstsc-rs --target IP --user foo --pass bar --dom enterprise
```

### Basic connection (using SSL without NLA)

You can disable nla with the `ssl` option, but if you want to logon with credentials, you need to specify the `auto` option :
```
mstsc-rs --target IP --user foo --pass bar --ssl --auto
```

### Pass the hash (using restricted admin mode)

Microsoft recently add some new feature for the NLA authentication. One of them is Restricted Admin Mode.
This mode allow an admin to use the `Network` authentication as `Interactive` authentication. This mode allow an admin to be authenticate only by its NTLM hash.

```
mstsc-rs --target IP --user foo --hash a4c37e22527cc1479a8d620d2953b6c0 --admin
```

### Check already logon User

In certain case, it's useful to use SSL in order to NLA.
When server doesn't enforce NLA, using SSL allow to view which are connected on the server without still the session :

```
mstsc-rs --target IP --ssl
```

When NLA is enforced, You can send blank credentials for the `Interactive` authentication by using the `blank` option :

```
mstsc-rs --target IP --user foo --pass bar --blank
```

### Tamper LogonType=10 to LogonType=7

When you mix `blank` option and `auto` option on a NLA session, you can logon without emmited `4624` with `LogonType=10` but with `LogonType=7` :
```
mstsc-rs --target IP --user foo --pass bar --blank --auto
```

### Tamper the client name

A RDP client send the client name. `mstsc-rs` allow a user to customize it :
```
mstsc-rs --target IP --user foo --pass bar --name mstsc
```

## Play with `rdp-rs` crate


