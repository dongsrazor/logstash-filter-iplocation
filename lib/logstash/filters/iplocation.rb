# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'ipaddr'

class IPRange
  attr_accessor :startip
  attr_accessor :endip
  attr_accessor :country
  attr_accessor :province
  attr_accessor :city
  attr_accessor :isp
  attr_accessor :reliability
  #attr_accessor :startint
  #attr_accessor :endint
  
  def initialize(startip, endip, country, province, city, isp, reliability)
    @startip = startip
    @endip = endip
    @country = country
    @province = province
    @city = city
    @isp = isp
    @reliability = reliability

    #@startint = IPAddr.new(@startip).to_i
    #@endint = IPAddr.new(@endip).to_i
  end

end

class FunshionIPDB
  def initialize(countrydb, citydb)
    @country_ipranges = []
    @city_ipranges = []
    t1 = Time.now()
    f = File.open(countrydb, "r")
    f.each do |line|
      startip, endip, country, province, isp, reliability = line.force_encoding('utf-8').split(',', 6)
      ipr = IPRange.new(startip, endip, country, province, '', isp, reliability)
      @country_ipranges.push(ipr)
    end
    t2 = Time.now()
    f = File.open(citydb, "r")
    f.each do |line|
      startip, endip, province, city, isp, reliability = line.force_encoding('utf-8').split(',', 6)
      ipr = IPRange.new(startip, endip, '中国', province, city, isp, reliability)
      @city_ipranges.push(ipr)
    end
    t3 = Time.now()
    puts t2 - t1
    puts t3 - t2
  end

  def _query(ipranges, ip)
    """查询风行库，得到ip信息，如果库中不存在，返回0
    r = 1时返回ip range"""
    #二分法查询ip
    lid = 0
    hid = ipranges.length - 1
    fip = IPAddr.new(ip).to_i

    while lid <= hid do
      mid = (lid + hid)/2
      startint = IPAddr.new(ipranges[mid].startip).to_i
      endint = IPAddr.new(ipranges[mid].endip).to_i
      if fip >= startint and fip <= endint
        return [ipranges[mid].startip, ipranges[mid].endip,
               ipranges[mid].country, ipranges[mid].province, ipranges[mid].city, ipranges[mid].isp,
               ipranges[mid].reliability]
      end
      if fip < startint
        hid = mid - 1
      end
      if fip > endint
        lid = mid + 1
      end
    end
    return false
  end
  
  def query_from_country(ip)
    return _query(@country_ipranges, ip)
  end

  def query_from_city(ip)
    return _query(@city_ipranges, ip)
  end

  def query(ip)
    result = query_from_city(ip)
    if result
      return result
    else
      return query_from_country(ip)
    end
  end

end


# This example filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::FSIP < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   iplocation {
  #     source => [client_ip]
  #   }
  # }
  #
  config_name "iplocation"
  
  # Replace the message with this value.
  config :source, :validate => :string, :default => "client_ip", :required => true
  config :uri, :validate => :string, :default => "http_request", :required => true
  

  public
  def register
    # Add instance variables 
    @fsdb = FunshionIPDB.new("/opt/logstash/vendor/iplocation/funshion.country.dat", "/opt/logstash/vendor/iplocation/funshion.city.dat")
  end # def register

  public
  def filter(event)

    if @source
      # Replace the event message with our message as configured in the
      # config file.
      startip, endip, country, province, city, isp, r = @fsdb.query(event[@source])
      event["client_country"] = country
      event["client_province"] = province 
      event["client_city"] = city
      event["client_isp"] = isp 
    end

    if @uri
      u = URI::parse(event[@uri])
      event["path"] = u.path
      event["query"] = u.query
    end
    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Example
