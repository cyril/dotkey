# Dotkey

A protocol for generating tamper-proof, signed URLs.

A Dotkey is a URL path segment that starts with a dot (`.`) and
contains a cryptographic signature. The server generates and verifies
Dotkeys; clients treat signed URLs as opaque links.

This specification defines the structure and computation rules for
Dotkey URLs. It is independent of any specific cryptographic algorithm,
programming language, or framework.

> Inspired by [URL Protection Through HMAC](https://blog.cyril.email/posts/2025-03-12/url-protection-through-hmac.html) by Cyril Kato.

---

## 1. Conventions

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" are to be
interpreted as described in
[RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

## 2. Definitions

**Dotkey** — A URL path segment consisting of a dot (U+002E) followed
by one or more Base64url characters. It carries a cryptographic
signature that authenticates the URL content preceding it and,
optionally, a server-provided context.

**Placeholder** — A string in a URL template that marks where a Dotkey
will be inserted during signing. The default placeholder is
`__TOKEN__`.

**Prefix** — The portion of the URL strictly before a given
placeholder (or Dotkey segment).

**Context** — An arbitrary byte string, chosen by the server, that is
appended to the prefix before signing. It allows the server to bind a
Dotkey to information not present in the URL (user identity, scope,
expiration, etc.). When absent, it defaults to the empty string,
making the signature a function of the prefix alone.

**Signing function** — Any keyed function that takes a secret key and
a message, and produces a byte sequence suitable for message
authentication. The choice of signing function is a server decision.

---

## 3. Dotkey format

A Dotkey is a complete path segment (delimited by `/`):

```
.{signature_chars}
```

- The segment MUST start with exactly one dot (U+002E).
- `{signature_chars}` MUST consist of one or more characters from the
  Base64url alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`) as defined in
  [RFC 4648 §5](https://www.ietf.org/rfc/rfc4648.txt), without
  padding.

### 3.1. Dotkey length

The Dotkey length `L` is the total number of characters in the
segment, including the leading dot. The server chooses `L` such that:

```
2 ≤ L ≤ E + 1
```

Where `E` is the number of Base64url characters produced by encoding
the full output of the signing function (without padding).

When `L < E + 1`, the encoded output is truncated to `L - 1`
characters (left prefix). Shorter Dotkeys trade security margin for
shorter URLs.

### 3.2. Multiple Dotkeys

A URL MAY contain multiple Dotkeys, each in a distinct path segment.
Each Dotkey MAY use a different key, signing function, context, and
Dotkey length. Dotkeys are computed left to right, each one's prefix
including all previously inserted Dotkeys (see §4.2).

---

## 4. Signing

### 4.1. Single Dotkey

Given a URL template, a secret key, a signing function, a Dotkey
length `L`, and an optional context:

1. **Prefix**: extract everything before the placeholder.
2. **Message**: concatenate the prefix (UTF-8) and the context bytes.
   If no context is provided, the message is the prefix alone.
3. **Sign**: apply the signing function to the message using the key.
4. **Encode**: Base64url without padding
   ([RFC 4648 §5](https://www.ietf.org/rfc/rfc4648.txt)).
5. **Truncate**: take the first `L - 1` characters.
6. **Replace**: substitute the placeholder with `.` followed by the
   truncated signature.

```
sign(template, key, func, L, context = "") →
  prefix    = template[0 .. index_of(placeholder) - 1]
  message   = utf8(prefix) + utf8(context)
  raw       = func(key, message)
  encoded   = base64url_no_pad(raw)
  signature = encoded[0 .. L - 2]
  return template.replace_first(placeholder, "." + signature)
```

### 4.2. Multiple Dotkeys

For a template with `N` placeholders (left to right), each with its
own key, signing function, Dotkey length, and optional context:

1. Process the first placeholder: compute prefix, sign with its
   context, substitute.
2. For each subsequent placeholder: compute the prefix of the
   partially signed URL (including previously inserted Dotkeys), sign
   with its own context, substitute.

```
sign_multi(template, dotkeys[]) →
  result = template
  for dk in dotkeys (left to right):
    idx       = index_of(dk.placeholder, result)
    prefix    = result[0 .. idx - 1]
    message   = utf8(prefix) + utf8(dk.context)
    raw       = dk.func(dk.key, message)
    encoded   = base64url_no_pad(raw)
    signature = encoded[0 .. dk.L - 2]
    result    = result.replace_first(dk.placeholder, "." + signature)
  return result
```

---

## 5. Verification

Given a signed URL and an ordered list of (key, signing function,
Dotkey length, context) tuples:

1. Locate all Dotkey segments (path segments matching
   `\.[A-Za-z0-9_-]+`) in order of appearance.
2. For each Dotkey (left to right): extract the prefix, compute the
   expected signature using the corresponding key, function, and
   context, and compare using a **constant-time** comparison.

```
verify(signed_url, verifiers[]) →
  dotkey_segments = find_all_dotkey_segments(signed_url)

  for v in verifiers:
    seg       = dotkey_segments[v.index]
    extracted = seg[1..]
    prefix    = signed_url[0 .. start_of(seg) - 1]
    message   = utf8(prefix) + utf8(v.context)
    raw       = v.func(v.key, message)
    expected  = base64url_no_pad(raw)[0 .. len(extracted) - 1]
    if not constant_time_equal(extracted, expected):
      return false

  return true
```

A Dotkey authenticates the URL content before it, plus the context.
Content after the Dotkey (including query parameters) is not covered.

---

## 6. Conformance

An implementation is conformant if it satisfies all of the following:

1. **Format.** Every Dotkey matches `\.[A-Za-z0-9_-]+`.
2. **Length.** Every Dotkey has exactly `L` characters.
3. **Determinism.** Same template, key, function, length, and context
   always produce the same signed URL.
4. **Round-trip.** A signed URL is accepted by verification with the
   same parameters.
5. **Tamper detection.** Modifying any character in the prefix or the
   context causes verification to fail.
6. **Chain integrity.** In a multi-Dotkey URL, modifying or removing
   any Dotkey causes all subsequent Dotkeys to fail verification.

---

## 7. Security considerations

**Algorithm choice.** Providers MUST choose a signing function with at
least 128 bits of security. The secret key MUST be generated by a
cryptographically secure random number generator.

**Scope.** A Dotkey does not authenticate content after it. Place
Dotkeys so that all security-relevant path segments precede them.
Query parameters are never authenticated; encode critical values into
the path or the context.

**Context usage.** The context parameter is suited for binding a
Dotkey to information the server controls: user identity, scope,
expiration timestamps, nonces. Since the context is not visible in the
URL, the server MUST store or be able to recompute it at verification
time.

**Replay.** A valid signed URL can be reused by anyone who obtains it.
To limit this, include an expiration timestamp in the context (or
path) and verify it server-side.

**Truncation.** With `L - 1` Base64url characters, there are
`64^(L-1)` possible values. Providers SHOULD use at least 11
characters of Dotkey length (≥ 60 bits) for security-relevant
purposes.

**Transport.** Always serve signed URLs over HTTPS.

**Path collisions.** Application routes SHOULD NOT use path segments
starting with `.` to avoid ambiguity.

---

## Appendix A. Test vectors (HMAC-SHA256, non-normative)

### A.1. Key

| Property  | Value                                                              |
|-----------|--------------------------------------------------------------------|
| Base64url | `whv00t28TCgBgJIGawcnLwNz0s15HW-u6JOoMTpVSSA=`                   |
| Hex       | `c21bf4d2ddbc4c28018092066b07272f0373d2cd791d6faee893a8313a554920` |

Default placeholder: `__TOKEN__`

### A.2. Single Dotkey vectors

#### Vector 1 — Full-length, no context

| Field         | Value                                                                           |
|---------------|---------------------------------------------------------------------------------|
| Dotkey length | 44                                                                              |
| Template      | `https://example.com/__TOKEN__/resource/42`                                     |
| Prefix        | `https://example.com/`                                                          |
| Context       | *(empty)*                                                                       |
| HMAC (hex)    | `36f46daa2c9d776e742bdea040e995632aaee4a5d78e1feee65a8241f4e08f0f`              |
| Signature     | `NvRtqiydd250K96gQOmVYyqu5KXXjh_u5lqCQfTgjw8`                                 |
| Signed URL    | `https://example.com/.NvRtqiydd250K96gQOmVYyqu5KXXjh_u5lqCQfTgjw8/resource/42` |

#### Vector 2 — Same prefix, different suffix

Same prefix as Vector 1, different template suffix. The Dotkey is
identical.

| Field      | Value                                                                                         |
|------------|-----------------------------------------------------------------------------------------------|
| Template   | `https://example.com/__TOKEN__/resource/42?action=delete`                                     |
| Signed URL | `https://example.com/.NvRtqiydd250K96gQOmVYyqu5KXXjh_u5lqCQfTgjw8/resource/42?action=delete` |

#### Vector 3 — Truncated (L = 9)

| Field         | Value                                       |
|---------------|---------------------------------------------|
| Dotkey length | 9                                           |
| Template      | `https://example.com/__TOKEN__/resource/42`  |
| Dotkey        | `.NvRtqiyd`                                  |
| Signed URL    | `https://example.com/.NvRtqiyd/resource/42`  |

#### Vector 4 — With context

Demonstrates that a context changes the signature even when the prefix
is identical to Vector 1.

| Field         | Value                                                                                    |
|---------------|------------------------------------------------------------------------------------------|
| Dotkey length | 44                                                                                       |
| Template      | `https://example.com/__TOKEN__/resource/42`                                              |
| Prefix        | `https://example.com/`                                                                   |
| Context       | `user=42`                                                                                |
| Message       | `https://example.com/user=42`                                                            |
| HMAC (hex)    | `71b4fd84d93aecc6b91429f95180d85d69eaf84f14c53d66a4f65da50f72d659`                       |
| Signature     | `cbT9hNk67Ma5FCn5UYDYXWnq-E8UxT1mpPZdpQ9y1lk`                                          |
| Signed URL    | `https://example.com/.cbT9hNk67Ma5FCn5UYDYXWnq-E8UxT1mpPZdpQ9y1lk/resource/42`          |

#### Vector 5 — Dotkey at end of path

| Field         | Value                                                                                          |
|---------------|------------------------------------------------------------------------------------------------|
| Dotkey length | 44                                                                                             |
| Template      | `https://example.com/resource/42/__TOKEN__?action=delete`                                      |
| Prefix        | `https://example.com/resource/42/`                                                             |
| HMAC (hex)    | `b91e34274f198e81e5657999858d5bacab89e601e4802f07fc454ac860a56feb`                             |
| Signed URL    | `https://example.com/resource/42/.uR40J08ZjoHlZXmZhY1brKuJ5gHkgC8H_EVKyGClb-s?action=delete` |

### A.3. Chained multi-Dotkey vector

**Keys:**

| Key   | Hex                                                              |
|-------|------------------------------------------------------------------|
| Key A | `c21bf4d2ddbc4c28018092066b07272f0373d2cd791d6faee893a8313a554920` |
| Key B | `ac616e61726965732d696e2d612d636f616c2d6d696e652d3132333435363738` |

**Configuration:**

| Dotkey   | Placeholder | Key   | Function    | Length | Context      |
|----------|-------------|-------|-------------|--------|--------------|
| Dotkey 1 | `__ALPHA__` | Key A | HMAC-SHA256 | 44     | *(empty)*    |
| Dotkey 2 | `__BETA__`  | Key B | HMAC-SHA256 | 13     | `scope=read` |

**Template:**

```
https://example.com/shop/__ALPHA__/product/42/__BETA__?color=red
```

**Dotkey 1** (prefix = `https://example.com/shop/`, no context):

| Field      | Value                                                          |
|------------|----------------------------------------------------------------|
| HMAC (hex) | `7029746925f663f346ff47353d8ff450cb28098c2e43507f376124e32b6ed5ef` |
| Dotkey     | `.cCl0aSX2Y_NG_0c1PY_0UMsoCYwuQ1B_N2Ek4ytu1e8`               |

**Dotkey 2** (prefix includes Dotkey 1, context = `scope=read`):

| Field      | Value                                                                                 |
|------------|---------------------------------------------------------------------------------------|
| Prefix     | `https://example.com/shop/.cCl0aSX2Y_NG_0c1PY_0UMsoCYwuQ1B_N2Ek4ytu1e8/product/42/` |
| HMAC (hex) | `b5848f6b0ac895ee5abea3ac9ed76cd1f2602fdd7b690f74c785341ba2edcb31`                    |
| Dotkey     | `.tYSPawrIle5a`                                                                       |

**Signed URL:**

```
https://example.com/shop/.cCl0aSX2Y_NG_0c1PY_0UMsoCYwuQ1B_N2Ek4ytu1e8/product/42/.tYSPawrIle5a?color=red
```

Modifying Dotkey 1 invalidates Dotkey 2 because Dotkey 1 is part of
Dotkey 2's prefix.

---

## 8. References

1. Josefsson, S. (2006). *The Base16, Base32, and Base64 Data Encodings*. [RFC 4648](https://www.ietf.org/rfc/rfc4648.txt).
2. Bradner, S. (1997). *Key words for use in RFCs to Indicate Requirement Levels*. [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).
3. Kato, C. (2025). *URL Protection Through HMAC: A Practical Approach*. [Blog post](https://blog.cyril.email/posts/2025-03-12/url-protection-through-hmac.html).
