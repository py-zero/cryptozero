# CryptoZero

Make it easy for learning groups to use simple cryptographic techniques in python


- Docs: ...
- Development: [https://github.com/py-zero/cryptozero](https://github.com/py-zero/cryptozero)
- Tests: ...

## API

### Verification
\# TODO: expose signing and verifying methods


### Secrecy
\# TODO: expose encryption and decryption methods


## Examples

### Verification


### Secrecy

### Key Stretching
Key stretching is the process of taking a weak password, and making it longer in such a way
that it is slow to compute. This is also called `hashing`.
An example would be taking the password `passw0rd`, and turning it into a series of bytes.

```python
from cryptozero.key import stretch
import base64
base64.urlsafe_b64encode(stretch('passw0rd'))
b'5ORsO6IvsHoxPXcaLRfe5Lx2Rt25apdJai9W7PGesBY='
```
We've use base64 as a nice way of showing the output.

#### Salting

stretching on its own, however, is not going to be enough. Someone can still come along and
break that password. What we need to do is mix in some `salt`.
As with a nice dish of Fish and Chips, the salt will compliment the password.

The salt will prevent an attacker from working out all the stretched keys ahead of time.

You can think of salting as adding some random characters onto your password.
```python
password = 'passw0rd'
salt = 'aofjdnvoekqoubsdvib3g7wefb'
salted_password = password + salt
secret_key = hasher(salted_password)
```
While this method gets you quite far, we have given you an easy way to do it securely.
```python
from cryptozero.key import stretch
import base64, os
password = 'passw0rd'
salt = os.urandom(16)
base64.urlsafe_b64encode(stretch(password, salt=salt))
b'd3sgGtHxsiESi0t4lkaXeep9j0ElfGeGMscpnfRz3vA='
```
Your output will be different. This is because we're getting a random salt using `os.urandom`.

You can safely give out the salt to people. In fact, it's very common to store the salt along side what you're encrypting.


### With networking
