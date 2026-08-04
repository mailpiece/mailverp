$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "mailverp"

class MailVerp
  class TestCase < Minitest::Test
    SECRET = "correct horse battery staple".freeze
    IDENTIFIER = "2f8x1qk".freeze
    DOMAIN = "mailer.example.com".freeze

    private
      def verp(secret: SECRET, **options)
        MailVerp.new(secret: secret, **options)
      end
  end
end
