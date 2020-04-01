require 'store/digest/http/version'
require 'uri/ni'
require 'xml/mixup'
require 'rack'
require 'rack/request'
require 'rack/response'

class Store::Digest::HTTP
  private

  DIGESTS = {
    md5:       16,
    "sha-1":   20,
    "sha-256": 32,
    "sha-384": 48,
    "sha-512": 64,
  }.freeze

  BASE      = /^\/+\.well-known\/+[dn]i\/+/.freeze
  POST_RAW  = '0c17e171-8cb1-4c60-9c58-f218075ae9a9'.freeze
  POST_FORM = '12d851b7-5f71-405c-bb44-bd97b318093a'.freeze
  DISPATCH  = {
    object: {}, meta: {}, partial: {},
    collection: {}, stats: {}, raw: {}, form: {},
  }

  DISPATCH[:object][:GET] = -> query, hdrs, body = nil do
    # note this can be anything
    ni  = URI('ni:///%s;%s' % query.values_at(:algorithm, :digest))
    obj = store.get ni

    resp = Rack::Response[404, [], []]

    return resp unless obj

    # overwrite ni uri
    ni = obj[store.primary]     # overwrite ni uri with canonical
    ct = obj.content            # make sure we have content
    lm = obj.mtime || obj.ctime # get last-modified

    # this is deleted
    if dt = obj.dtime or !ct
      dt ||= lm
      resp.status = 410
      resp.set_header 'Last-Modified', obj.dtime.rfc822
      return resp
    end

    # set up the final response
    resp.status = 304
    resp.set_header 'Last-Modified', lm.rfc822
    resp.set_header 'ETag', '"%s"' % ni.to_s
    resp.set_header 'Content-Location',
      "/.well-known/ni/#{ni.algorithm}/#{ni.b64digest}"

    # check etag
    if inm = hdrs['If-None-Match']
      inm = inm.split(/\s*,+\s*/).map { |i| i.tr_s ?", '' }
      return resp unless (obj.digests.values.map(&:to_s) & inm).empty?
    end

    # check if-modified-since
    if ims = hdrs['If-Modified-Since']
      ims.gsub!(/^([^,]*(?:,[^,]*)?)(?:\s*,.*)?$/, "\\1")
      if ims = Time.httpdate(ims).getgm rescue nil
        return resp if ims >= lm
      end
    end

    # set headers
    type = obj.type
    type << ";charset=#{obj.charset}" if obj.charset
    resp.set_header 'Content-Type', type
    resp.set_header 'Content-Encoding', obj.encoding if obj.encoding

    # return 200
    resp.status = 200
    resp.body   = ct

    resp
  end

  public

  attr_reader :store, :post_raw, :post_form

  def initialize store, base: nil, post_raw: nil, post_form: nil, param_map: nil
    @store     = store
    @base      = base      || BASE
    @post_raw  = post_raw  || POST_RAW
    @post_form = post_form || POST_FORM
  end

  def call env
    warn env.inspect
    # do surgery to request scheme
    env['HTTPS'] = 'on' if
      env['REQUEST_SCHEME'] and env['REQUEST_SCHEME'].downcase == 'https'

    req   = Rack::Request.new env
    uri   = URI(req.base_url) + env['REQUEST_URI']
    path  = uri.path.gsub(/^\/+\.well-known\/+ni\/+/, '').split(/\/+/, -1)
    query = req.GET.transform_keys(&:to_sym)
    body  = req.body

    # dispatch type
    disp = if path.empty?
             :stats
           elsif store.algorithms.include? path.first.to_sym
             if slug = path[1]
               if slug.empty?
                 :collection
               elsif !/^[0-9A-Za-z_-]+$/.match?(slug)
                 return [404, [], []]
               else
                 # determine if we have a whole digest or just part of one
                 algo = query[:algorithm] = path.first.to_sym

                 query[:digest] = slug

                 if /^[0-9A-Za-z_-]+$/.match?(slug) and
                     slug.length == (DIGESTS[algo] * 4/3.0).ceil
                   :object
                 elsif /^[0-9A-Fa-f]+$/.match?(slug) and
                     slug.length == DIGESTS[algo] * 2
                   query[:radix] = 16

                   :object
                 else
                   :partial
                 end
               end
             else
               # redirect 307
               return Rack::Response[307,  [['Location', newuri]], []]
             end
           elsif path.first == post_raw
             :raw
           elsif path.first == post_form
             # 415 unsupported media type
             # XXX EXPLAIN THIS
             return [415, [], []] unless
               req.get_header('Content-Type') == 'multipart/form-data'

             # 409 conflict
             # XXX EXPLAIN THIS
             return Rack::Response[409, [], []] unless
               req.POST.values.any? do |f|
               f.is_a? Rack::Multipart::UploadedFile 
             end

             # XXX here is where we would set the date from the
             # multipart header but rack doesn't have a way of doing this

             :raw
           else
             # 404 again  
           end

    if methods = DISPATCH[disp]
      m = (req.request_method == 'HEAD' ? 'GET' : req.request_method).to_sym
      if func = methods[m]
        begin
          resp = instance_exec query, req.env.dup, body, &func
          resp = Rack::Response[*resp] if resp.is_a? Array
        rescue Exception => e
          warn "wah #{e}"
          return [500, [], []]
        end

        resp.body = nil if req.request_method == 'HEAD'

        return resp.to_a
      else
        return [405, [], []]
      end
    else
      return [404, [], []]
    end
  end
end
