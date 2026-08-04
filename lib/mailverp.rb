require "openssl"

require "mailverp/version"

# Signed VERP addresses: build a per-message envelope sender, read the id back.
class MailVerp
  DEFAULT_PREFIX = "bounces".freeze
  DEFAULT_SEPARATOR = "+".freeze
  DEFAULT_TAG_SEPARATOR = ".".freeze
  DEFAULT_HMAC_LENGTH = 24
  DEFAULT_DIGEST = "SHA256".freeze

  MAX_LOCAL_PART_BYTESIZE = 64  # RFC 5321 §4.5.3.1.1
  MAX_DOMAIN_BYTESIZE = 253     # RFC 1035 §3.1
  MAX_ADDRESS_BYTESIZE = 254    # RFC 5321 §4.5.3.1.3, minus path brackets
  IDENTIFIER_PATTERN = /\A[a-z0-9_-]+\z/.freeze

  DOMAIN_LABEL = /[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?/.freeze
  DOMAIN_PATTERN = /\A#{DOMAIN_LABEL}(?:\.#{DOMAIN_LABEL})*\z/.freeze

  def initialize(secret:, prefix: DEFAULT_PREFIX, separator: DEFAULT_SEPARATOR,
    tag_separator: DEFAULT_TAG_SEPARATOR, hmac_length: DEFAULT_HMAC_LENGTH, digest: DEFAULT_DIGEST)
    @secrets = Array(secret)
    raise ArgumentError, "secret must not be empty" if @secrets.empty?

    @prefix = prefix
    @separator = separator
    @tag_separator = tag_separator
    @hmac_length = hmac_length
    @digest = digest
    @pattern = build_pattern
  end

  # Signed envelope sender for `identifier`, bound to `domain`. Validated for MAIL FROM.
  def address_for(identifier, domain:)
    if !identifier.to_s.match?(IDENTIFIER_PATTERN)
      raise ArgumentError, "identifier #{identifier.inspect} is not safe for a local part " \
        "(expected #{IDENTIFIER_PATTERN.inspect})"
    elsif !valid_domain?(domain)
      raise ArgumentError, "domain #{domain.inspect} is not a valid DNS name " \
        "(punycode it yourself if it's internationalized)"
    elsif local_part(identifier, domain).bytesize > MAX_LOCAL_PART_BYTESIZE
      raise ArgumentError, "identifier #{identifier.inspect} is too long " \
        "(max #{max_identifier_length} characters with this configuration)"
    elsif address(identifier, domain).bytesize > MAX_ADDRESS_BYTESIZE
      raise ArgumentError, "address for #{identifier.inspect}@#{domain} is too long " \
        "(max #{MAX_ADDRESS_BYTESIZE} octets)"
    else
      address(identifier, domain)
    end
  end

  # Identifier from `address`, or nil if shape/domain/HMAC fail. Never raises.
  def identifier_for(address)
    domain = domain_of(address)
    if valid_domain?(domain) &&
        (match = @pattern.match(local_part_of(address))) &&
        valid_hmac?(match[:id], domain, match[:hmac])
      match[:id]
    end
  end

  # Shape check only - does not verify the HMAC.
  def address?(address)
    !!@pattern.match(local_part_of(address))
  end

  # Longest id that fits a 64-octet local part; a long domain can still overflow.
  def max_identifier_length
    MAX_LOCAL_PART_BYTESIZE - @prefix.bytesize - @separator.bytesize - @tag_separator.bytesize - @hmac_length
  end

  private
    def build_pattern
      /\A#{Regexp.escape(@prefix)}#{Regexp.escape(@separator)}(?<id>[a-z0-9_-]+)
        #{Regexp.escape(@tag_separator)}(?<hmac>[0-9a-f]{#{@hmac_length}})\z/x
    end

    # Plausible DNS name within RFC 1035 limits. IDN must already be punycode.
    def valid_domain?(domain)
      domain = domain.to_s
      domain.bytesize <= MAX_DOMAIN_BYTESIZE && DOMAIN_PATTERN.match?(domain)
    end

    def local_part(identifier, domain)
      "#{@prefix}#{@separator}#{identifier}#{@tag_separator}#{hmac_for(identifier, domain)}"
    end

    def address(identifier, domain)
      "#{local_part(identifier, domain)}@#{domain}"
    end

    def domain_of(address)
      address.to_s.split("@", 2).last.to_s.downcase
    end

    def local_part_of(address)
      address.to_s.split("@", 2).first.to_s.downcase
    end

    def valid_hmac?(identifier, domain, hmac)
      @secrets.any? { |secret| OpenSSL.secure_compare(hmac, hmac_for(identifier, domain, secret: secret)) }
    end

    # NUL-joined prefix/id/domain so field boundaries and domain can't be shifted.
    def hmac_for(identifier, domain, secret: @secrets.first)
      message = [ @prefix, identifier.to_s, domain.to_s.downcase ].join("\0")
      OpenSSL::HMAC.hexdigest(@digest, secret, message)[0, @hmac_length]
    end
end
