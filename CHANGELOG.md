# Changelog

## Unreleased

- Reject a blank or non-string secret, and an `hmac_length` outside 8 to the digest's length
- Return nil, not raise, from `identifier_for` and `address?` on a badly encoded address, and fold only ASCII case

## 0.5.0

Initial public release.
