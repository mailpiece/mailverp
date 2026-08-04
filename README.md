# mailverp

📮 Signed VERP addresses for Ruby.

Build a one-off, signed envelope sender for each outbound message, and read the identifier back when a bounce arrives. **mailverp** signs the identifier with an HMAC, so a return path can't be forged or mined for valid addresses.

For mail senders that need to know which specific delivery a bounce refers to: transactional email systems tracking per-message delivery status, mailing list software isolating bounces per subscriber, multi-tenant relays that need one return path per tenant.

**mailverp** handles:

- Builds a tagged, signed envelope sender (`address_for`) and reads the identifier back out of one (`identifier_for`)
- The signature covers the prefix, identifier, and domain together, so a tag minted for one domain is not valid at another - see [What Is Signed](#what-is-signed)
- Constant-time HMAC verification (`OpenSSL.secure_compare`) - no timing oracle on the tag
- Secret rotation: an array of secrets, the first signs, any of them verifies
- Configurable prefix, sub-address and tag separators, HMAC length, and digest
- `max_identifier_length` so a caller can check an identifier fits before, not after, delivery
- No network, no state, zero runtime dependencies

> mailverp signs and reads back a delivery identifier. What that delivery is, and what a bounce means, stay in your code.

## Contents

- [Installation](#installation)
- [Building an Address](#building-an-address)
- [Reading One Back](#reading-one-back)
- [Secret Rotation](#secret-rotation)
- [Local-Part Length](#local-part-length)
- [Character Safety](#character-safety)
- [Separators](#separators)
- [What Is Signed](#what-is-signed)
- [Limitations](#limitations)
- [Testing](#testing)
- [History](#history)
- [Contributing](#contributing)
- [License](#license)

## Installation

Add this line to your application's Gemfile:

```ruby
gem "mailverp"
```

Requires Ruby >= 3.4

## Building an Address

```ruby
verp = MailVerp.new(secret: "...", prefix: "bounces")   # optional: separator:, tag_separator:, hmac_length:, digest:

verp.address_for("2f8x1qk", domain: "mailer.example.com")
# => "bounces+2f8x1qk.a1b2c3d4e5f6a7b8c9d0e1f2@mailer.example.com"
```

- **secret** - a string, or an array for [rotation](#secret-rotation)
- **prefix** - the local-part prefix before the identifier; defaults to `"bounces"`
- The identifier is yours to choose. It's opaque to this library - a delivery id, most naturally - and is not stored or looked up here

Anything that wouldn't make a legal reverse-path raises `ArgumentError`: an identifier outside the [safe alphabet](#character-safety), a `domain` that isn't a plausible DNS name, or a combination too long for [the octet limits](#local-part-length). Building an address is something your own code controls, so bad input here is a bug, not routine input - unlike reading one back.

The result is placed directly into a `MAIL FROM` command by whatever sends the message, which is why both arguments are validated rather than trusted: a `domain` carrying a `\r\n` could otherwise inject SMTP commands of its own. A domain is letters, digits, `-`, and `.` in RFC 1035 labels, nothing else - so IDN domains must already be punycode, since this library makes no attempt to convert them.

## Reading One Back

```ruby
verp.identifier_for("bounces+2f8x1qk.a1b2c3d4e5f6a7b8c9d0e1f2@mailer.example.com")
# => "2f8x1qk"

verp.identifier_for("bounces+2f8x1qk.deadbeefdeadbeefdeadbeef@mailer.example.com")
# => nil, the HMAC doesn't verify

verp.identifier_for("someone@example.com")
# => nil, wrong shape entirely
```

`identifier_for` never raises. A bounce arriving at a stale, forged, or unrelated address is routine rather than exceptional - a late bounce carries the address a delivery used months ago - so an unreadable one comes back nil like any other.

`address?` checks the shape only - useful to tell a VERP address from an ordinary one before deciding whether to look further - and does not verify the HMAC:

```ruby
verp.address?("bounces+2f8x1qk.deadbeefdeadbeefdeadbeef@mailer.example.com") # => true, shape only
verp.identifier_for("bounces+2f8x1qk.deadbeefdeadbeefdeadbeef@mailer.example.com") # => nil, doesn't verify
```

## Secret Rotation

Pass an array. The first secret signs every new address; every secret in the array is tried when reading one back:

```ruby
verp = MailVerp.new(secret: [ "new-secret", "old-secret" ])
```

To rotate: prepend the new secret ahead of the old one, deploy, and let the old secret ride along until every address it signed has stopped arriving - however long you keep a delivery around is a reasonable bound. Then drop it.

## Local-Part Length

RFC 5321 §4.5.3.1.1 caps a local part at 64 octets, and §4.5.3.1.3 caps a complete reverse-path at 256 octets including its brackets - 254 for the bare `local@domain` this library builds. `address_for` raises rather than emit an address most MTAs will refuse. `max_identifier_length` reports the longest identifier that still fits a 64-octet local part, given the current prefix, separators, and HMAC length:

```ruby
verp.max_identifier_length # => 31
```

That figure is the local-part budget only - it doesn't know what `domain:` you'll call `address_for` with, and a long enough domain can still push the two past 254 octets together. An id bounded by construction (a UUID, say) always fits; anything else is worth checking here first, with `address_for` the final word once the domain is known.

## Character Safety

An identifier is only ever placed in a local part, so it's restricted to `a-z`, `0-9`, `_`, and `-` - nothing that requires quoting, and no `+` or `.`, which this library uses as separators. `address_for` raises on anything else.

Uppercase is not in that alphabet, deliberately: some MTAs lower-case a local part in transit even though RFC 5321 says they shouldn't, so an identifier distinguished only by case would not survive the round trip. Reading one back matches the whole local part case-insensitively for the same reason.

## Separators

`prefix+identifier.hmac` is the default shape - `+` is the widely-recognized sub-address delimiter (RFC 5233), and most receivers preserve whatever follows it back to you unchanged. Both separators are configurable:

```ruby
MailVerp.new(secret: "...", prefix: "vb", separator: "-", tag_separator: "_")
# vb-2f8x1qk_a1b2c3d4e5f6a7b8c9d0e1f2@...
```

Some inbound gateways strip or mangle a `+` before it reaches you. If that's a problem for your relay, change `separator` - `-` and `_` are the common substitutes.

## What Is Signed

- The HMAC covers the prefix, the identifier, and the domain together, joined with a `NUL` byte so the field boundaries can't be shifted - a tag isn't `hmac(identifier)`, it's `hmac(prefix, identifier, domain)`
- An address is only valid at the domain it was minted for. The same identifier, re-addressed to another domain, does not verify - this is what makes it safe to run one secret across a multi-tenant relay, where each tenant gets its own return path
- An address is only valid under the prefix it was minted with. Swapping `bounces+` for anything else, even with the original hmac carried over, does not verify
- The domain is matched case-insensitively when signing, since DNS is case-insensitive and an MTA may rewrite the case of a local part or domain in transit
- Validation runs before signing, in both directions - `identifier_for` rejects a malformed domain on shape alone, before it would even compute an HMAC to compare

## Limitations

- **Not a bounce parser.** This library builds and reads addresses only. Parsing what a bounce says - a DSN, an SMTP rejection - is [mailbounce](https://github.com/mailpiece/mailbounce)'s job.
- **Not a domain or delivery lookup.** The identifier is opaque here; resolving it to an actual record, and deciding which domain a return path belongs to, is the application's job.
- **No transport.** This library never opens a socket. What you do with the address it builds, and what arrives at the address it reads, are both up to you.

## Testing

```sh
bundle install
rake
```

## History

View the [changelog](CHANGELOG.md).

## Contributing

Everyone is encouraged to help improve this project:

- [Report bugs](https://github.com/mailpiece/mailverp/issues)
- Fix bugs and submit pull requests
- Write, clarify, or fix documentation
- Suggest or add new features

## Acknowledgments

View the [acknowledgments](ACKNOWLEDGMENTS.md).

## License

MIT. See [LICENSE](LICENSE).