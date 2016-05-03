module LogStash; module Outputs; class ElasticSearch; class HttpClient;
  class Pool
    class NoConnectionAvailableError < Error; end
    class HostUnreachableError < Error;
      attr_reader :original_error, :url

      def initialize(original_error, url)
        @original_error = original_error
        @url = url
      end

      def message
        "[#{original_error.class}] #{original_error.message}"
      end
    end
    
    attr_reader :logger

    DEFAULT_OPTIONS = {
      :healthcheck_path => '/'.freeze,
      :scheme => 'http',
      :resurrect_interval => 5,
      :auth => nil, # Can be set to {:user => 'user', :password => 'pass'}
      :sniffing => false,
      :sniffer_delay => 10,
    }.freeze

    def initialize(logger, adapter, urls=[], options={})
      @logger = logger
      @adapter = adapter
      @urls = urls

      DEFAULT_OPTIONS.merge(options).tap do |merged|
        @healthcheck_path = merged[:healthcheck_path]
        @scheme = merged[:scheme]
        @resurrect_interval = merged[:resurrect_interval]
        @auth = merged[:auth]
        @sniffing = merged[:sniffing]
        @sniffer_delay = merged[:sniffer_delay]
      end

      # Override the scheme if one is explicitly set in urls
      if @urls.any? {|u| u.scheme == 'https'} && @scheme == 'http'
        raise ArgumentError, "HTTP was set as scheme, but an HTTPS URL was passed in!"
      end

      # Used for all concurrent operations in this class
      @state_mutex = Mutex.new

      # Holds metadata about all URLs
      @url_info = {}
      @stopping = false

      update_urls(urls)
      start_resurrectionist
      start_sniffer if @sniffing
    end

    def close
      @state_mutex.synchronize { @stopping = true }

      logger.debug  "Stopping sniffer"
      stop_sniffer

      logger.debug  "Stopping resurrectionist"
      stop_resurrectionist

      logger.debug  "Waiting for in use manticore connections"
      wait_for_in_use_connections

      logger.debug("Closing adapter #{@adapter}")
      @adapter.close
    end

    def wait_for_in_use_connections
      until in_use_connections.empty?
        logger.info "Blocked on shutdown to in use connections #{@state_mutex.synchronize {@url_info}}"
        sleep 1
      end
    end

    def in_use_connections
      @state_mutex.synchronize { @url_info.values.select {|v| v[:in_use] > 0 } }
    end

    def alive_urls_count
      @state_mutex.synchronize { @url_info.values.select {|v| !v[:dead] }.count }
    end

    def until_stopped(task_name)
      until @state_mutex.synchronize { @stopping }
        begin
          yield
        rescue => e
          logger.warn(
            "Error while performing #{task_name}",
            :message => e.message,
            :class => e.class.name,
            :backtrace => e.backtrace
            )
        end
      end
    end

    def start_sniffer
      @sniffer = Thread.new do
        until_stopped("sniffing") { sniff! }
      end
    end

    # Sniffs the cluster then updates the internal URLs
    def sniff!
      update_urls(check_sniff)
    end

    ES1_SNIFF_RE_URL  = /\[([^\/]*)?\/?([^:]*):([0-9]+)\]/
    ES2_SNIFF_RE_URL  = /([^\/]*)?\/?([^:]*):([0-9]+)/
    # Sniffs and returns the results. Does not update internal URLs!
    def check_sniff
      resp = perform_request('GET', '_nodes')
      parsed = LogStash::Json.load(resp.body)
      parsed['nodes'].map do |id,info|
        # TODO Make sure this works with shield. Does that listed
        # stuff as 'https_address?'
        addr_str = info['http_address'].to_s
        next unless addr_str # Skip hosts with HTTP disabled


        # Only connect to nodes that serve data
        # this will skip connecting to client, tribe, and master only nodes
        # Note that if 'attributes' is NOT set, then that's just a regular node
        # with master + data + client enabled, so we allow that
        attributes = info['attributes']
        next if attributes && attributes['data'] == 'false'

        matches = addr_str.match(ES1_RE_URL) || addr_str.match(ES2_RE_URL)
        if matches
          host = matches[1].empty? ? matches[2] : matches[1]
          port = matches[3]
          info.merge :host => host, :port => port, :id => id
        end
      end.compact
    end

    def stop_sniffer
      @sniffer.join if @sniffer
    end

    def start_resurrectionist
      @resurrectionist = Thread.new do
        last_resurrect = Time.now
        until_stopped("resurrecting") do
          if Time.now-last_resurrect >= @resurrect_interval
            last_resurrect = Time.now
            resurrect_dead!
          end
        end
      end
    end

    def resurrect_dead!
      # Try to keep locking granularity low such that we don't affect IO...
      @state_mutex.synchronize { @url_info.select {|url,meta| meta[:dead] } }.each do |url,meta|
        begin
          @logger.info("Checking url #{url} with path #{@healthcheck_path} to see if node resurrected")
          perform_request_to_url(url, "HEAD", @healthcheck_path)
          # If no exception was raised it must have succeeded!
          logger.warn("Resurrected connection to dead ES instance at #{url}")
          @state_mutex.synchronize { meta[:dead] = false }
        rescue HostUnreachableError => e
          logger.debug("Attempted to resurrect connection to dead ES instance at #{url}, got an error [#{e.class}] #{e.message}")
        end
      end
    end

    def stop_resurrectionist
      @resurrectionist.join
    end

    def perform_request(method, path, params={}, body=nil)
      with_connection do |url|
        resp = perform_request_to_url(url, method, path, params, body)
        [url, resp]
      end
    end

    [:get, :put, :post, :delete, :patch, :head].each do |method|
      define_method(method) do |path, params={}, body=nil|
        perform_request(method, path, params, body)
      end
    end

    def perform_request_to_url(url, method, path, params={}, body=nil)
      res = @adapter.perform_request(url, method, path, params, body)
    rescue *@adapter.host_unreachable_exceptions => e
      logger.error "[#{e.class}] #{e.message} #{url}"
      raise HostUnreachableError.new(e, url), "Could not reach host #{e.class}: #{e.message}"
    end

    def normalize_url(uri)
      raise ArgumentError, "Only URI objects may be passed in!" unless uri.is_a?(URI)
      uri = uri.clone

      # Set credentials if need be
      if @auth && !uri.user
        uri.user ||= @auth[:user]
        uri.password ||= @auth[:password]
      end

      uri.scheme = @scheme

      uri
    end

    def update_urls(new_urls)
      # Normalize URLs
      new_urls = new_urls.map(&method(:normalize_url))

      @state_mutex.synchronize do
        # Add new connections
        new_urls.each do |url|
          # URI objects don't have real hash equality! So, since this isn't perf sensitive we do a linear scan
          unless @url_info.keys.include?(url)
            logger.info("Elasticsearch pool adding node @ URL #{url}")
            add_url(url)
          end
        end

        # Delete connections not in the new list
        @url_info.each do |url,_|
          unless new_urls.include?(url)
            logger.info("Elasticsearch pool removing node @ URL #{url}")
            remove_url(url)
          end
        end
      end
    end

    def size
      @state_mutex.synchronize { @url_info.size }
    end

    def add_url(url)
      @url_info[url] ||= empty_url_meta
    end

    def remove_url(url)
      @url_info.delete(url)
    end

    def empty_url_meta
      {
        :in_use => 0,
        :dead => false
      }
    end

    def with_connection
      url, url_meta = get_connection

      # Custom error class used here so that users may retry attempts if they receive this error
      # should they choose to
      raise NoConnectionAvailableError, "No Available connections" unless url
      yield url
    rescue HostUnreachableError => e
      mark_dead(url, e)
      raise e
    ensure
      return_connection(url)
    end

    def mark_dead(url, error)
      @state_mutex.synchronize do
        url_meta = @url_info[url]
        logger.warn("Marking url #{url} as dead. Last error: [#{error.class}] #{error.message}")
        url_meta[:dead] = true
        url_meta[:last_error] = error
      end
    end

    def url_meta(url)
      @state_mutex.synchronize do
        @url_info[url]
      end
    end

    def get_connection
      @state_mutex.synchronize do
        # The goal here is to pick a random connection from the least-in-use connections
        # We want some randomness so that we don't hit the same node over and over, but
        # we also want more 'fair' behavior in the event of high concurrency
        eligible_set = nil
        lowest_value_seen = nil
        @url_info.each do |url,meta|
          meta_in_use = meta[:in_use]
          next if meta[:dead]

          if lowest_value_seen.nil? || meta_in_use < lowest_value_seen
            lowest_value_seen = meta_in_use
            eligible_set = [[url, meta]]
          elsif lowest_value_seen == meta_in_use
            eligible_set << [url, meta]
          end
        end

        return nil if eligible_set.nil?

        pick, pick_meta = eligible_set.sample
        pick_meta[:in_use] += 1

        [pick, pick_meta]
      end
    end

    def return_connection(url)
      @state_mutex.synchronize do
        if @url_info[url] # Guard against the condition where the connection has already been deleted
          @url_info[url][:in_use] -= 1
        end
      end
    end
  end
end; end; end; end;
