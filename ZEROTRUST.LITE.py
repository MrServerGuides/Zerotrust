import os
import sys
import json
import base64
import random
from Crypto.Cipher import AES, ChaCha20_Poly1305, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

def aes_gcm_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag

def aes_gcm_decrypt(ct, key, iv, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)

def chacha20_encrypt(data, key, nonce):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag

def chacha20_decrypt(ct, key, nonce, tag):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def blowfish_encrypt(data, key, iv):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    pad_len = Blowfish.block_size - (len(data) % Blowfish.block_size)
    data += bytes([pad_len]) * pad_len
    return cipher.encrypt(data)

def blowfish_decrypt(ct, key, iv):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    data = cipher.decrypt(ct)
    pad = data[-1]
    return data[:-pad]

def xor_bytes(data, key):
    return bytes(a ^ b for a, b in zip(data, key))

def shift_bytes(data, val):
    return bytes((b + val) % 256 for b in data)

def unshift_bytes(data, val):
    return bytes((b - val) % 256 for b in data)

def shuffle(data, order):
    return bytes(data[i] for i in order)

def unshuffle(data, order):
    inv = [0] * len(order)
    for i, p in enumerate(order): inv[p] = i
    return bytes(data[i] for i in inv)

def sha256_hex(data):
    h = SHA256.new(); h.update(data); return h.hexdigest()

def encrypt_once(data):
    info = {}
    k1, iv1 = get_random_bytes(32), get_random_bytes(12)
    c1, t1 = aes_gcm_encrypt(data, k1, iv1)
    info.update({"aes_key": base64.b64encode(k1).decode(), "aes_iv": base64.b64encode(iv1).decode(), "aes_tag": base64.b64encode(t1).decode()})
    k2, n2 = get_random_bytes(32), get_random_bytes(12)
    c2, t2 = chacha20_encrypt(c1, k2, n2)
    info.update({"chacha_key": base64.b64encode(k2).decode(), "chacha_iv": base64.b64encode(n2).decode(), "chacha_tag": base64.b64encode(t2).decode()})
    k3 = get_random_bytes(len(c2))
    x = xor_bytes(c2, k3)
    info["xor_key"] = base64.b64encode(k3).decode()
    sv = random.randint(1, 255)
    s = shift_bytes(x, sv)
    info["shift_val"] = sv
    order = list(range(len(s)))
    random.shuffle(order)
    sh = shuffle(s, order)
    info["shuffle_order"] = order
    k4, iv4 = get_random_bytes(16), get_random_bytes(8)
    b = blowfish_encrypt(sh, k4, iv4)
    info.update({"bf_key": base64.b64encode(k4).decode(), "bf_iv": base64.b64encode(iv4).decode()})
    final = base64.b64encode(b)
    info["sha256"] = sha256_hex(final)
    return final, info

def multi_encrypt(data, layers):
    keys = []
    d = data
    for _ in range(layers):
        d, ki = encrypt_once(d)
        keys.append(ki)
    return d, keys

def multi_decrypt(enc, keys):
    d = enc
    for ki in reversed(keys):
        if sha256_hex(d) != ki["sha256"]:
            raise ValueError("SHA256 mismatch: integrity check failed")
        b = base64.b64decode(d)
        sh = blowfish_decrypt(b, base64.b64decode(ki["bf_key"]), base64.b64decode(ki["bf_iv"]))
        u = unshuffle(sh, ki["shuffle_order"])
        v = unshift_bytes(u, ki["shift_val"])
        x = xor_bytes(v, base64.b64decode(ki["xor_key"]))
        c1 = chacha20_decrypt(x, base64.b64decode(ki["chacha_key"]), base64.b64decode(ki["chacha_iv"]), base64.b64decode(ki["chacha_tag"]))
        d = aes_gcm_decrypt(c1, base64.b64decode(ki["aes_key"]), base64.b64decode(ki["aes_iv"]), base64.b64decode(ki["aes_tag"]))
    return d

def main():
    console.print(Panel("[bold cyan]ZEROTRUST - V2 LITE - A MULTI ENCRYPTION WITH THE BEST ENCRYPTION[/]", expand=True))
    payload = console.input("[green]Enter payload .py file to encrypt:[/] ").strip()
    if not os.path.isfile(payload): console.print("[red]File not found[/]"); sys.exit(1)
    out = console.input("[green]Enter output .py filename:[/] ").strip()
    layers = console.input("[green]Number of layers to apply:[/] ").strip()
    try:
        layers = int(layers); assert layers > 0
    except:
        console.print("[red]Invalid number of layers[/]"); sys.exit(1)

    data = open(payload, 'rb').read()

    console.print(Panel(f"[yellow]Encrypting with {layers} layer(s)...[/]", expand=False))
    enc, keys = multi_encrypt(data, layers)

    console.print(Panel("[yellow]Verifying encryption with 90 checks...[/]", expand=False))
    with Progress(SpinnerColumn(), BarColumn(), TextColumn("[{task.completed}/{task.total}]"), TimeElapsedColumn()) as prog:
        task = prog.add_task("Checking", total=90)
        for _ in range(90):
            if multi_decrypt(enc, keys) != data:
                console.print("[red]Verification failed![/]"); sys.exit(2)
            prog.update(task, advance=1)

    stub = f"""
import base64, json
from Crypto.Cipher import AES, ChaCha20_Poly1305, Blowfish
from Crypto.Hash import SHA256

encrypted = '{enc.decode()}'
keys_info = {json.dumps(keys)}

def aes_gcm_decrypt(ct, key, iv, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)

def chacha20_decrypt(ct, key, nonce, tag):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def blowfish_decrypt(ct, key, iv):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    data = cipher.decrypt(ct)
    pad = data[-1]
    return data[:-pad]

def xor_bytes(data, key): return bytes(a ^ b for a, b in zip(data, key))

def unshift_bytes(data, val): return bytes((b - val) % 256 for b in data)

def unshuffle(data, order):
    inv = [0]*len(order)
    for i,p in enumerate(order): inv[p] = i
    return bytes(data[i] for i in inv)

def sha256_hex(data):
    h = SHA256.new(); h.update(data); return h.hexdigest()

def multi_decrypt(enc_b64, keys):
    d = enc_b64
    for ki in reversed(keys):
        if sha256_hex(d) != ki['sha256']:
            raise ValueError('Integrity check failed')
        b = base64.b64decode(d)
        sh = blowfish_decrypt(b, base64.b64decode(ki['bf_key']), base64.b64decode(ki['bf_iv']))
        us = unshift_bytes(unshuffle(sh, ki['shuffle_order']), ki['shift_val'])
        x = xor_bytes(us, base64.b64decode(ki['xor_key']))
        c1 = chacha20_decrypt(x, base64.b64decode(ki['chacha_key']), base64.b64decode(ki['chacha_iv']), base64.b64decode(ki['chacha_tag']))
        d = aes_gcm_decrypt(c1, base64.b64decode(ki['aes_key']), base64.b64decode(ki['aes_iv']), base64.b64decode(ki['aes_tag']))
    return d

if __name__=='__main__':
    enc_bytes = encrypted.encode()
    data = multi_decrypt(enc_bytes, keys_info)
    exec(data, globals())
"""
    with open(out, 'w') as f: f.write(stub)
    os.chmod(out, 0o755)
    console.print(Panel(f"[green]Done! Created {out}[/]", style="green"))

if __name__ == '__main__':
    main()
