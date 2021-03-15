## RSA

### Requirements

Install kscript: https://github.com/holgerbrandl/kscript#installation

make sure script is executable
```shell
$ chmod +x rsa.kts
```

### Usage

#### To generate key pair
```shell
$ ./rsa.kts --keygen
```

Will generate `key` and `key.pub` files, to specify key destination pass `--privatekey <path>` or/and `--publickey <path>`

```shell
$ ./rsa.kts --keygen --privatekey private.key --publickey public.key
```

#### To encrypt a file
```shell
$ ./rsa.kts --encrypt msg.txt > enc.txt
```

By default, will try to read `key.pub` file, to use a different public key use `--publickey <path>`
```shell
$ ./rsa.kts --encrypt msg.txt --publickey public.key > enc2.txt
```

#### To decrypt a file
```shell
$ ./rsa.kts --decrypt enc.txt > dec.txt
```
By default, will try to read `key` file, to use a different public key use `--privatekey <path>`

```shell
$ ./rsa.kts --decrypt enc2.txt --privatekey private.key > dec2.txt
```
