# Dotkey

A protocol for generating tamper-proof, signed URLs.

A Dotkey is a URL path segment that starts with a dot (`.`) and
contains a cryptographic signature. The server generates and verifies
Dotkeys; clients treat signed URLs as opaque links.

This specification defines the **structure and computation rules** for
Dotkey URLs. It is independent of any specific cryptographic algorithm,
programming language, or framework.

> Inspired by [URL Protection Through HMAC](https://blog.cyril.email/posts/2025-03-12/url-protection-through-hmac.html) by Cyril Kato.

---

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
and "MAY" in this document are to be interpreted as described in
[RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

## 2. Definitions

**Dotkey** — A URL path segment consisting of a dot (U+002E) followed
by one or more Base64url characters. A Dotkey carries a cryptographic
signature (or a prefix thereof) that authenticates the portion of the
URL that precedes it.

**Provider** — The entity (typically a web server) that generates and
verifies Dotkeys. The provider chooses the signing algorithm, the
secret key, and the Dotkey length.

**Placeholder** — A string in a URL template that marks the position
where a Dotkey will be inserted during signing. The default placeholder
is `__TOKEN__`. Implementations MAY support configurable placeholders.

**Signing function** — Any keyed function that takes a secret key and
a message, and produces a fixed-length or variable-length byte
sequence suitable for message authentication. The choice of signing
function is a provider decision and is outside the scope of this
specification.

**Prefix** — The portion of the URL that precedes a given placeholder
(or Dotkey segment). Each Dotkey authenticates its own prefix.

---

## 3. Dotkey format

A Dotkey is a **complete path segment** (delimited by `/`) with the
following structure:

```
.{signature_chars}
```

Where:

- The segment MUST start with exactly one dot (U+002E).
- `{signature_chars}` MUST consist of one or more characters from the
  Base64url alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`) as defined in
  [RFC 4648 §5](https://www.ietf.org/rfc/rfc4648.txt), without
  padding.
- The segment MUST NOT contain `/`.

### 3.1. Dotkey length

The **Dotkey length** is the total number of characters in the
segment, including the leading dot. It is a fixed value chosen by the
provider.

The provider MUST choose a Dotkey length `L` such that:

```
2 ≤ L ≤ E + 1
```

Where `E` is the number of Base64url characters (without padding)
produced by encoding the full output of the signing function.

When `L < E + 1`, the encoded output is **truncated** to `L - 1`
characters (left prefix). Shorter Dotkeys trade security margin for
shorter URLs; longer Dotkeys provide stronger tamper-resistance.

### 3.2. Multiple Dotkeys

A URL MAY contain **multiple Dotkeys**, each in a distinct path
segment. Each Dotkey MAY use a different secret key, signing function,
and Dotkey length. Dotkeys are computed sequentially from left to
right, each one authenticating everything that precedes it (see §4.2).

---

## 4. Signing

### 4.1. Single Dotkey

Given a URL template containing a placeholder, a secret key, a signing
function, and a Dotkey length `L`:

1. **Compute the prefix**: extract everything in the template **before**
   the first occurrence of the placeholder.
2. **Compute the signature**: apply the signing function to the prefix
   (encoded as UTF-8 bytes) using the secret key.
3. **Encode**: encode the raw output as Base64url
   ([RFC 4648 §5](https://www.ietf.org/rfc/rfc4648.txt)) **without
   padding** (strip trailing `=`).
4. **Truncate**: take the first `L - 1` characters of the encoded
   string.
5. **Assemble**: replace the first occurrence of the placeholder in the
   original template with `.` followed by the truncated signature.

```
sign(template, key, func, L, placeholder) →
  prefix    = template[0 .. index_of(placeholder)-1]
  raw       = func(key, utf8(prefix))
  encoded   = base64url_no_pad(raw)
  signature = encoded[0 .. L-2]
  return template.replace_first(placeholder, "." + signature)
```

Because the signing input is only the prefix, **two URLs that share
the same prefix before the placeholder produce the same Dotkey**,
regardless of what follows (path or query parameters).

### 4.2. Multiple Dotkeys

Given a URL template containing `N` placeholders (left to right), each
associated with its own secret key, signing function, and Dotkey
length:

1. **For the first placeholder**: compute the prefix (everything before
   it), sign, and substitute the Dotkey into the template.
2. **For each subsequent placeholder**: compute the prefix of the
   **partially signed** URL (everything before this placeholder,
   including previously inserted Dotkeys), sign, and substitute.

Each Dotkey's prefix includes all preceding Dotkeys. This creates a
left-to-right chain: the second Dotkey depends on the first, the third
depends on the second, and so on.

```
sign_multi(template, dotkeys[]) →
  result = template
  for dk in dotkeys (left to right):
    idx       = index_of(dk.placeholder, result)
    prefix    = result[0 .. idx-1]
    raw       = dk.func(dk.key, utf8(prefix))
    encoded   = base64url_no_pad(raw)
    signature = encoded[0 .. dk.L-2]
    result    = result.replace_first(dk.placeholder, "." + signature)
  return result
```

---

## 5. Verification

Given a signed URL and an ordered list of (key, signing function,
Dotkey length) tuples corresponding to each Dotkey from left to right:

1. **Locate all Dotkey segments**: find every path segment that starts
   with `.` and whose remaining characters belong to the Base64url
   alphabet, in order of appearance.
2. **For each Dotkey** (left to right): extract the prefix (everything
   in the URL before the Dotkey segment), compute the expected
   signature with the appropriate key and signing function, encode as
   Base64url without padding, truncate to the length of the extracted
   signature, and compare using a **constant-time** comparison
   function.

```
verify(signed_url, verifiers[]) →
  dotkey_segments = find_all_dotkey_segments(signed_url)

  for v in verifiers:
    seg       = dotkey_segments[v.index]
    extracted = seg[1..]                  // strip leading dot
    prefix    = signed_url[0 .. start_of(seg)-1]
    raw       = v.func(v.key, utf8(prefix))
    expected  = base64url_no_pad(raw)[0 .. len(extracted)-1]
    if not constant_time_equal(extracted, expected):
      return false

  return true
```

### 5.1. Scope of authentication

A Dotkey authenticates **only the URL content that precedes it**.
Content after the last Dotkey in the path (including query parameters)
is **not** covered by any signature.

Providers SHOULD place Dotkeys at the **end of the path segment they
intend to protect**. When a Dotkey is the last path segment, the
entire path up to that point is authenticated.

---

## 6. Conformance

An implementation is **conformant** if it satisfies all of the
following structural properties, regardless of the signing function
used:

1. **Format.** Every Dotkey produced is a complete path segment
   matching the pattern `\.[A-Za-z0-9_-]+`.
2. **Length.** Every Dotkey has exactly `L` characters, where `L` is
   the provider-configured Dotkey length.
3. **Prefix signing.** The signing input for a Dotkey is the URL
   content strictly before that Dotkey's position.
4. **Determinism.** Given the same template, key, signing function, and
   Dotkey length, the output is always the same signed URL.
5. **Prefix invariance.** Two URLs that share the same prefix before
   the placeholder MUST produce the same Dotkey, regardless of what
   follows.
6. **Round-trip.** A URL produced by signing MUST be accepted by
   verification with the same key and signing function.
7. **Tamper detection.** Modifying any character in the prefix of a
   signed URL MUST cause verification to fail.
8. **Chain integrity.** In a multi-Dotkey URL, modifying or removing
   any Dotkey MUST cause all subsequent Dotkeys to fail verification.

---

## 7. Security considerations

**Algorithm choice.** This specification does not mandate a signing
function. Providers MUST choose an algorithm that provides at least
128 bits of security against forgery. The secret key MUST be generated
by a cryptographically secure random number generator and MUST be of
sufficient length for the chosen algorithm.

**Scope of protection.** A Dotkey does not authenticate content after
it. Providers MUST position Dotkeys so that all security-relevant path
segments precede the Dotkey. Query parameters are never authenticated;
if query parameter integrity matters, encode the relevant values into
the path before the Dotkey.

**Replay protection.** A valid signed URL can be reused by anyone who
obtains it. For sensitive operations, include an `expires` timestamp
in the query string and verify it server-side. For critical one-time
actions, add a nonce and track it server-side.

**User binding.** A signed URL without user context is transferable.
Include a session identifier or user ID in the path before the Dotkey
when the URL SHOULD be restricted to a specific user.

**Truncation trade-off.** Shorter Dotkeys reduce the cost of
brute-forcing a valid signature. With `L - 1` Base64url characters,
there are `64^(L-1)` possible values. A Dotkey length of 2
(1 character of signature) offers only 64 possibilities and MUST NOT
be used for security-sensitive operations. Providers SHOULD NOT use
fewer than 11 characters of Dotkey length (≥ 60 bits of entropy) for
any security-relevant purpose.

**Revocation.** Revoking a single signed URL requires a server-side
deny-list. Rotating the secret key invalidates all outstanding signed
URLs using that key.

**Transport.** Always serve signed URLs over HTTPS. The signature
protects integrity, not confidentiality.

**Path collisions.** Application routes SHOULD NOT include path
segments starting with `.` to avoid ambiguity with Dotkey segments.

---

## Appendix A. Example test vectors (non-normative)

The following vectors use **HMAC-SHA256** as the signing function.
They are provided as a convenience for implementers choosing this
algorithm. They are **not** part of the conformance criteria.

### A.1. Key

| Property   | Value                                                            |
|------------|------------------------------------------------------------------|
| Base64url  | `whv00t28TCgBgJIGawcnLwNz0s15HW-u6JOoMTpVSSA=`                 |
| Hex        | `c21bf4d2ddbc4c28018092066b07272f0373d2cd791d6faee893a8313a554920` |
| Length     | 32 bytes (256 bits)                                              |

Default placeholder: `__TOKEN__`

### A.2. Single Dotkey vectors

#### Vector 1 — Full-length Dotkey

| Field             | Value                                                                                     |
|-------------------|-------------------------------------------------------------------------------------------|
| Dotkey length     | 44 (maximum for SHA-256)                                                                  |
| Template          | `https://example.com/__TOKEN__/resource/42`                                               |
| Prefix            | `https://example.com/`                                                                    |
| HMAC (hex)        | `36f46daa2c9d776e742bdea040e995632aaee4a5d78e1feee65a8241f4e08f0f`                        |
| Signature (43 ch) | `NvRtqiydd250K96gQOmVYyqu5KXXjh_u5lqCQfTgjw8`                                           |
| Dotkey            | `.NvRtqiydd250K96gQOmVYyqu5KXXjh_u5lqCQfTgjw8`                                          |
| Signed URL        | `https://example.com/.NvRtqiydd250K96gQOmVYyqu5KXXjh_u5lqCQfTgjw8/resource/42`           |

#### Vector 2 — Same prefix, different suffix

Demonstrates that the same prefix produces the same Dotkey regardless
of what follows.

| Field             | Value                                                                                                          |
|-------------------|----------------------------------------------------------------------------------------------------------------|
| Dotkey length     | 44                                                                                                             |
| Template          | `https://example.com/__TOKEN__/resource/42?action=delete`                                                      |
| Prefix            | `https://example.com/`                                                                                         |
| Dotkey            | `.NvRtqiydd250K96gQOmVYyqu5KXXjh_u5lqCQfTgjw8`                                                               |
| Signed URL        | `https://example.com/.NvRtqiydd250K96gQOmVYyqu5KXXjh_u5lqCQfTgjw8/resource/42?action=delete`                  |

The Dotkey is identical to Vector 1.

#### Vector 3 — Truncated Dotkey (9 characters)

| Field             | Value                                                       |
|-------------------|-------------------------------------------------------------|
| Dotkey length     | 9                                                           |
| Template          | `https://example.com/__TOKEN__/resource/42`                 |
| Prefix            | `https://example.com/`                                      |
| Full signature    | `NvRtqiydd250K96gQOmVYyqu5KXXjh_u5lqCQfTgjw8`              |
| Truncated (8 ch)  | `NvRtqiyd`                                                  |
| Dotkey            | `.NvRtqiyd`                                                 |
| Signed URL        | `https://example.com/.NvRtqiyd/resource/42`                 |

#### Vector 4 — Minimum Dotkey (2 characters)

| Field             | Value                                                       |
|-------------------|-------------------------------------------------------------|
| Dotkey length     | 2 (minimum)                                                 |
| Template          | `https://example.com/__TOKEN__/resource/42`                 |
| Prefix            | `https://example.com/`                                      |
| Truncated (1 ch)  | `N`                                                         |
| Dotkey            | `.N`                                                        |
| Signed URL        | `https://example.com/.N/resource/42`                        |

#### Vector 5 — Dotkey at end of path (recommended)

Demonstrates the recommended placement where the Dotkey is the last
path segment, authenticating the full path.

| Field             | Value                                                                                          |
|-------------------|------------------------------------------------------------------------------------------------|
| Dotkey length     | 44                                                                                             |
| Template          | `https://example.com/resource/42/__TOKEN__?action=delete`                                      |
| Prefix            | `https://example.com/resource/42/`                                                             |
| HMAC (hex)        | `b91e34274f198e81e5657999858d5bacab89e601e4802f07fc454ac860a56feb`                             |
| Signature (43 ch) | `uR40J08ZjoHlZXmZhY1brKuJ5gHkgC8H_EVKyGClb-s`                                               |
| Signed URL        | `https://example.com/resource/42/.uR40J08ZjoHlZXmZhY1brKuJ5gHkgC8H_EVKyGClb-s?action=delete` |

### A.3. Chained multi-Dotkey vector

This vector demonstrates two chained Dotkeys where the second Dotkey's
prefix includes the first Dotkey.

**Keys:**

| Key   | Base64url                                        | Hex                                                              |
|-------|--------------------------------------------------|------------------------------------------------------------------|
| Key A | `whv00t28TCgBgJIGawcnLwNz0s15HW-u6JOoMTpVSSA=`  | `c21bf4d2ddbc4c28018092066b07272f0373d2cd791d6faee893a8313a554920` |
| Key B | `rGFuYXJpZXMtaW4tYS1jb2FsLW1pbmUtMTIzNDU2Nzg=`  | `ac616e61726965732d696e2d612d636f616c2d6d696e652d3132333435363738` |

**Configuration:**

| Dotkey   | Placeholder  | Key   | Signing function | Dotkey length |
|----------|--------------|-------|------------------|---------------|
| Dotkey 1 | `__ALPHA__`  | Key A | HMAC-SHA256      | 44 (full)     |
| Dotkey 2 | `__BETA__`   | Key B | HMAC-SHA256      | 13 (truncated)|

**Template:**

```
https://example.com/shop/__ALPHA__/product/42/__BETA__?color=red
```

**Dotkey 1** (Key A, prefix = `https://example.com/shop/`):

| Field             | Value                                                          |
|-------------------|----------------------------------------------------------------|
| Prefix            | `https://example.com/shop/`                                    |
| HMAC (hex)        | `7029746925f663f346ff47353d8ff450cb28098c2e43507f376124e32b6ed5ef` |
| Signature (43 ch) | `cCl0aSX2Y_NG_0c1PY_0UMsoCYwuQ1B_N2Ek4ytu1e8`                |
| Dotkey            | `.cCl0aSX2Y_NG_0c1PY_0UMsoCYwuQ1B_N2Ek4ytu1e8`               |

**Dotkey 2** (Key B, prefix includes Dotkey 1):

| Field             | Value                                                                                           |
|-------------------|-------------------------------------------------------------------------------------------------|
| Prefix            | `https://example.com/shop/.cCl0aSX2Y_NG_0c1PY_0UMsoCYwuQ1B_N2Ek4ytu1e8/product/42/`           |
| HMAC (hex)        | `a3e9559fccb04a846b7e2ed712d31a74bcac01a2f04eb230b2c38ecd7f56bc53`                              |
| Full signature    | `o-lVn8ywSoRrfi7XEtMadLysAaLwTrIwssOOzX9WvFM`                                                 |
| Truncated (12 ch) | `o-lVn8ywSoRr`                                                                                  |
| Dotkey            | `.o-lVn8ywSoRr`                                                                                 |

**Signed URL:**

```
https://example.com/shop/.cCl0aSX2Y_NG_0c1PY_0UMsoCYwuQ1B_N2Ek4ytu1e8/product/42/.o-lVn8ywSoRr?color=red
```

Modifying Dotkey 1 invalidates Dotkey 2 because Dotkey 1 is part of
Dotkey 2's prefix.

---

## 8. References

1. Josefsson, S. (2006). *The Base16, Base32, and Base64 Data Encodings*. [RFC 4648](https://www.ietf.org/rfc/rfc4648.txt).
2. Bradner, S. (1997). *Key words for use in RFCs to Indicate Requirement Levels*. [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).
3. Kato, C. (2025). *URL Protection Through HMAC: A Practical Approach*. [Blog post](https://blog.cyril.email/posts/2025-03-12/url-protection-through-hmac.html).
