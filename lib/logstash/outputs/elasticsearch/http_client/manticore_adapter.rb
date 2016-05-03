require 'manticore'

module LogStash; module Outputs; class ElasticSearch; class HttpClient;
  class ManticoreAdapter
    attr_reader :manticore, :logger

    def initialize(logger, options)
      @logger = logger
      @options = options || {}

      client_options = @options[:transport_options] || {}
      client_options[:ssl] = @options[:ssl] || {}

      @request_options = @options[:headers] ? {:headers => @options[:headers]} : {}
      @manticore = ::Manticore::Client.new(client_options)
    end

    # Performs the request by invoking {Transport::Base#perform_request} with a block.
    #
    # @return [Response]
    # @see    Transport::Base#perform_request
    #
    def perform_request(url, method, path, params={}, body=nil)
      params = (params || {}).merge @request_options
      params[:body] = body if body
      url_and_path = (url + path).to_s # Convert URI object to string

      case method
      when :get
        resp = @manticore.get(url_and_path, params)
      when :head
        resp = @manticore.head(url_and_path, params)
      when :put
        resp = @manticore.put(url_and_path, params)
      when :post
        resp = @manticore.post(url_and_path, params)
      when :delete
        resp = @manticore.delete(url_and_path, params)
      else
        raise ArgumentError.new "Method #{method} not supported"
      end

      resp
    end

    def close
      @manticore.close
    end

    def host_unreachable_exceptions
      [::Manticore::Timeout,::Manticore::SocketException, ::Manticore::ClientProtocolException, ::Manticore::ResolutionFailure, Manticore::SocketTimeout]
    end
  end
end; end; end; end
