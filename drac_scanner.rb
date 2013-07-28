require 'net/http'
require 'uri'

# Scans a subnet for Dell DRAC default installations. Each server has a web
# interface that is installed on port 443 by default.
#
# It doesn't return anything programmatically useful. It just tells you if a
# host is compromised.
#
# Usage:
#
#   require 'drac_scanner'
#   scanner = DracScanner.new('172.15.222.5/30')
#   scanner.scan!
#
class DracScanner

  attr_reader :address, :prefix

  def initialize(address_and_prefix)
    address, prefix = address_and_prefix.split('/')
    prefix = prefix.to_i

    if valid_address?(address)
      @address = address
    else
      raise ArgumentError, "Invalid IP #{ip.inspect}"
    end

    if valid_prefix?(prefix)
      @prefix = prefix
    else
      raise ArgumentError, "Invalid CIDR #{prefix.inspect}"
    end
  end

  def scan!
    threads = []
    each_host do |host|
      threads << Thread.new(host) do |host|
        attempt_login(host)
      end
    end
    threads.each(&:join)
  end

  private

  def attempt_login(host)
    params = {
      'WEBVAR_PASSWORD' => 'calvin',
      'WEBVAR_USERNAME' => 'root',
      'WEBVAR_ISCMCLOGIN' => 0
    }

    headers = {
      "User-Agent" => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv =>14.0) Gecko/20100101 Firefox/14.0.1",
      "Accept" => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language" => "en-us,en;q=0.5",
      "Accept-Encoding" => "gzip, deflate",
      "Connection" => "keep-alive",
      "Content-Type" => "application/x-www-form-urlencoded; charset=UTF-8",
      "Referer" => "https://#{host}/Applications/dellUI/login.htm",
      "Content-Length" => 63,
      "Cookie" => "test=1; SessionLang=EN",
      "Pragma" => "no-cache",
      "Cache-Control" => "no-cache"
    }
    uri = URI.parse("https://#{host}/Applications/dellUI/RPC/WEBSES/create.asp")

    # Build request
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.open_timeout = 5
    request = Net::HTTP::Post.new(uri.path)
    request.set_form_data(params)
    headers.each do |key, value|
      request.add_field(key, value)
    end
    begin
      response = http.request(request)
    rescue Timeout::Error
      # If the request times out, keep calm and carry on...
    else
      if response.body.include?("'USERNAME' : 'root'")
        print "Dell DRAC compromised! Credentials: root:calvin for IP: #{host}"
      end
    end
  end

  # Returns the network address as an unsigned 32-bit number
  def address_u32
    octets = @address.split('.').map(&:to_i)
    (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + (octets[3])
  end

  # Returns the prefix as an unsigned 32-bit number
  def prefix_u32
    (0xffffffff >> (32 - @prefix) << (32 - @prefix))
  end

  # Returns the network address as an unsigned 32-bit number
  def network_u32
    address_u32 & prefix_u32
  end

  # Returns the broadcast address as an unsigned 32-bit number
  def broadcast_u32
    network_u32 + ((2 ** (32 - @prefix)) - 1)
  end

  # Returns a normal address from a 32-bit address
  def parse_u32(u32, prefix)
    [u32].pack('N').unpack('C4').join('.')
  end

  # Itereates over all the hosts for a given network
  def each_host
    (network_u32+1..broadcast_u32-1).each do |i|
      yield parse_u32(i, @prefix)
    end
  end

  def valid_address?(address)
    if /\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z/ =~ address
      return $~.captures.all? {|i| i.to_i < 256}
    end
    false
  end

  def valid_prefix?(prefix)
    (0..32).include?(prefix)
  end
end

