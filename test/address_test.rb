require_relative "test_helper"

class MailVerp::AddressTest < MailVerp::TestCase
  def setup
    @verp = verp
    @address = @verp.address_for(IDENTIFIER, domain: DOMAIN)
  end

  def test_round_trip
    assert_equal IDENTIFIER, @verp.identifier_for(@address)
  end

  def test_address_shape
    assert_match(/\Abounces\+2f8x1qk\.[0-9a-f]{24}@mailer\.example\.com\z/, @address)
  end

  def test_address_predicate_is_a_shape_check_only
    forged = @address.sub(/\.[0-9a-f]{24}@/, ".000000000000000000000000@")

    assert @verp.address?(@address)
    assert @verp.address?(forged)
    assert_nil @verp.identifier_for(forged)
  end

  def test_tampered_hmac_does_not_verify
    last_hex_digit = @address.match(/[0-9a-f](?=@)/)[0]
    flipped_digit = last_hex_digit == "0" ? "1" : "0"
    tampered = @address.sub(/#{last_hex_digit}@/, "#{flipped_digit}@")

    assert_nil @verp.identifier_for(tampered)
  end

  def test_tampered_identifier_does_not_verify
    tampered = @address.sub(IDENTIFIER, "2f8x1qz")

    assert_nil @verp.identifier_for(tampered)
  end

  def test_wrong_secret_does_not_verify
    assert_nil verp(secret: "different").identifier_for(@address)
  end

  def test_secret_rotation_signs_with_the_first_and_verifies_with_any
    old_verp = verp(secret: "old-secret")
    rotated = verp(secret: [ "new-secret", "old-secret" ])

    old_address = old_verp.address_for(IDENTIFIER, domain: DOMAIN)
    new_address = rotated.address_for(IDENTIFIER, domain: DOMAIN)

    assert_equal IDENTIFIER, rotated.identifier_for(old_address)
    assert_equal IDENTIFIER, rotated.identifier_for(new_address)
    refute_equal old_address, new_address
  end

  def test_secret_not_in_rotation_does_not_verify
    rotated = verp(secret: [ "new-secret", "old-secret" ])
    unrelated = verp(secret: "unrelated-secret")

    address = unrelated.address_for(IDENTIFIER, domain: DOMAIN)

    assert_nil rotated.identifier_for(address)
  end

  def test_empty_secret_list_is_rejected
    assert_raises(ArgumentError) { verp(secret: []) }
  end

  def test_wrong_prefix_does_not_match
    other = verp(prefix: "return")

    assert_nil other.identifier_for(@address)
    refute other.address?(@address)
  end

  def test_signature_is_bound_to_the_prefix_not_just_the_identifier
    hmac = @address[/\.([0-9a-f]+)@/, 1]
    relabelled = "return+#{IDENTIFIER}.#{hmac}@#{DOMAIN}"

    # Same secret, same identifier, same hmac - only the prefix differs, and
    # that alone must be enough to fail: the signature covers the prefix.
    assert_nil verp(prefix: "return").identifier_for(relabelled)
  end

  def test_signature_is_bound_to_the_domain
    address = @verp.address_for(IDENTIFIER, domain: "mailer.tenant-a.example.com")
    relocated = address.sub("tenant-a", "tenant-b")

    assert_nil @verp.identifier_for(relocated)
  end

  def test_domain_case_differences_still_verify
    address = @verp.address_for(IDENTIFIER, domain: "Mailer.Example.com")

    assert_equal IDENTIFIER, @verp.identifier_for(address)
    assert_equal IDENTIFIER, @verp.identifier_for(address.sub("Mailer.Example.com", "mailer.example.com"))
    assert_equal IDENTIFIER, @verp.identifier_for(address.sub("Mailer.Example.com", "MAILER.EXAMPLE.COM"))
  end

  def test_signing_frames_the_prefix_and_identifier_apart
    # prefix "a" + identifier "bc" and prefix "ab" + identifier "c" concatenate
    # to the same bytes ("abc") without unambiguous framing between fields.
    shifted_left = verp(secret: "shared-secret", prefix: "a", separator: "")
    shifted_right = verp(secret: "shared-secret", prefix: "ab", separator: "")

    address_left = shifted_left.address_for("bc", domain: "example.com")
    address_right = shifted_right.address_for("c", domain: "example.com")

    refute_equal address_left[/\.([0-9a-f]+)@/, 1], address_right[/\.([0-9a-f]+)@/, 1]
  end

  def test_malformed_input_reports_nothing
    assert_nil @verp.identifier_for("not-an-address-at-all")
    assert_nil @verp.identifier_for("bounces+missing-hmac@example.com")
    assert_nil @verp.identifier_for("someone@example.com")
    assert_nil @verp.identifier_for(nil)
    assert_nil @verp.identifier_for("")

    refute @verp.address?("not-an-address-at-all")
    refute @verp.address?(nil)
  end

  def test_over_long_identifier_is_rejected
    too_long = "a" * (@verp.max_identifier_length + 1)

    assert_raises(ArgumentError) { @verp.address_for(too_long, domain: DOMAIN) }
  end

  def test_identifier_at_the_length_limit_is_accepted
    exactly_fits = "a" * @verp.max_identifier_length
    address = @verp.address_for(exactly_fits, domain: DOMAIN)

    assert_equal exactly_fits, @verp.identifier_for(address)
  end

  def test_a_25_character_uuid_identifier_fits_under_the_default_configuration
    # 25 is this app's real identifier length: a UUIDv7 base36-encoded to 25 characters
    # (see PostRider's AGENTS.md) - the actual thing @verp signs in production.
    uuid_like_identifier = "0hne8z3xjq1r9kf6b2vwmc4st"

    assert_equal 25, uuid_like_identifier.length
    assert uuid_like_identifier.length <= @verp.max_identifier_length
  end

  def test_unsafe_characters_are_rejected
    assert_raises(ArgumentError) { @verp.address_for("has space", domain: DOMAIN) }
    assert_raises(ArgumentError) { @verp.address_for("has+plus", domain: DOMAIN) }
    assert_raises(ArgumentError) { @verp.address_for("Has-Upper", domain: DOMAIN) }
    assert_raises(ArgumentError) { @verp.address_for("has.dot", domain: DOMAIN) }
  end

  def test_lookup_is_case_insensitive_to_survive_mtas_that_fold_case
    assert_equal IDENTIFIER, @verp.identifier_for(@address.upcase)
  end

  def test_custom_separators
    custom = verp(prefix: "vb", separator: "-", tag_separator: "_")
    address = custom.address_for(IDENTIFIER, domain: DOMAIN)

    assert_match(/\Avb-2f8x1qk_[0-9a-f]{24}@mailer\.example\.com\z/, address)
    assert_equal IDENTIFIER, custom.identifier_for(address)
    assert_nil @verp.identifier_for(address)
  end

  def test_custom_hmac_length_and_digest
    custom = verp(hmac_length: 8, digest: "SHA1")
    address = custom.address_for(IDENTIFIER, domain: DOMAIN)

    assert_match(/\Abounces\+2f8x1qk\.[0-9a-f]{8}@mailer\.example\.com\z/, address)
    assert_equal IDENTIFIER, custom.identifier_for(address)
  end

  def test_max_identifier_length_reflects_configuration
    assert verp(prefix: "b").max_identifier_length > @verp.max_identifier_length
  end

  def test_domain_with_crlf_is_rejected
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: "x.com\r\nRCPT TO:<v@x.com>") }
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: "x.com\nDATA") }
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: "x.com\r") }
  end

  def test_domain_with_nul_is_rejected
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: "x.com\0evil") }
  end

  def test_domain_with_angle_brackets_or_space_is_rejected
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: "x.com>") }
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: "<x.com") }
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: "x .com") }
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: "x\"com") }
  end

  def test_domain_without_a_label_is_rejected
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: "") }
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: ".") }
  end

  def test_control_character_in_a_domain_is_rejected_before_the_hmac_is_compared
    # Sign the injected domain too, so this isn't the (already verified)
    # domain-binding check catching a mismatch: validation must reject the
    # shape on its own, before any HMAC comparison runs.
    injected_domain = "mailer.example.com\r\nRCPT TO:<attacker@evil.example>"
    hmac = @verp.send(:hmac_for, IDENTIFIER, injected_domain)
    forged = "bounces+#{IDENTIFIER}.#{hmac}@#{injected_domain}"

    assert_nil @verp.identifier_for(forged)
  end

  def test_over_253_octet_domain_is_rejected
    too_long_domain = "#{"a" * 63}.#{"b" * 63}.#{"c" * 63}.#{"d" * 60}.com"

    assert too_long_domain.bytesize > MailVerp::MAX_DOMAIN_BYTESIZE
    assert_raises(ArgumentError) { @verp.address_for("abc", domain: too_long_domain) }
  end

  def test_over_254_octet_total_address_is_rejected
    # Individually legal identifier and domain, illegal only once combined.
    long_domain = "#{"a" * 60}.#{"b" * 60}.#{"c" * 60}.#{"d" * 55}.com"
    identifier = "a" * @verp.max_identifier_length

    assert long_domain.bytesize <= MailVerp::MAX_DOMAIN_BYTESIZE
    assert_raises(ArgumentError) { @verp.address_for(identifier, domain: long_domain) }
  end

  def test_punycode_domain_is_accepted
    address = @verp.address_for(IDENTIFIER, domain: "xn--80ak6aa92e.com")

    assert_equal IDENTIFIER, @verp.identifier_for(address)
  end
end
