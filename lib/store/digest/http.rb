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


  COERCIONS = {
    string:  -> str { str.to_s },
    symbol:  -> sym { sym.to_s.to_sym },
    integer: -> int { int.to_i },
    time:    -> time do
      return time if time.is_a? Time
      return time.to_time if time.is_a? DateTime
      time = time.to_s + 'T00:00:00Z' if /^\d{4}-\d\d-\d\d$/.match? time.to_s
      Time.iso8601 time.to_s rescue nil
    end
  }.freeze

  COERCE_MAP = {
    size:            [:size,     COERCIONS[:integer]],
    created:         [:ctime,    COERCIONS[:time]],
    modified:        [:mtime,    COERCIONS[:time]],
    "meta-modified": [:ptime,    COERCIONS[:time]],
    deleted:         [:dtime,    COERCIONS[:time]],
    boundary:        [:boundary, COERCIONS[:integer]],
  }

  def uri_query uri
    out = {}
    if uri.query
      URI.decode_www_form(uri.query).each do |k, v|
        k  = k.to_sym
        out[k] ||= []
        out[k] << v
      end
    end
    out
  end

  def coerce_query query
    out = {}

    # let's force this into an assoc and treat it like it may have the
    # keys repeated (as in URI.decode_www_form)
    query.to_a.each do |q|
      raise ArgumentError, "#{q.inspect} must be an array" unless q.is_a? Array

      # when flattened, the first element is the key and subsequent
      # elements are values
      k, *v = q.flatten
      k = k.to_sym
      if COERCE_MAP.key? k
        # rewrite outside keys to inside keys
        k, coerce = COERCE_MAP[k]
        v.map! { |x| coerce.call x if x and !x.to_s.empty? }
      end
      # this will collate and append any values
      out.key?(k) ? out[k] += v : out[k] = v
    end

    out
  end

  # this will do for now
  def serialize_query hash
    hash.to_a.map do |pair|
      k, *v = pair.flatten
      v.map { |x| [k.to_s, x.to_s].join ?= }
    end.flatten.join(?&).gsub(/\+/, '%2B')
  end

  BASE      = /^\/+\.well-known\/+[dn]i\/+/.freeze
  POST_RAW  = '0c17e171-8cb1-4c60-9c58-f218075ae9a9'.freeze
  POST_FORM = '12d851b7-5f71-405c-bb44-bd97b318093a'.freeze
  DISPATCH  = {
    object: {}, meta: {}, partial: {},
    collection: {}, stats: {}, raw: {}, form: {},
  }

  DISPATCH[:object][:GET] = -> uri, query, hdrs, body = nil do
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
      resp.set_header 'Last-Modified', dt.getgm.rfc822
      return resp
    end

    # set up the final response
    resp.status = 304
    resp.set_header 'Last-Modified', lm.getgm.rfc822
    resp.set_header 'ETag', '"%s"' % ni.to_s
    cl = "/.well-known/ni/#{ni.algorithm}/#{ni.b64digest}"
    resp.set_header 'Content-Location', cl if cl != uri.request_uri

    cc = %w[HTTP_CACHE_CONTROL HTTP_PRAGMA].map do |h|
      (hdrs[h] || '').split(/s*,+\s*/)
    end.flatten.map(&:downcase).uniq

    unless cc.include? 'no-cache'
      # check etag
      if inm = hdrs['HTTP_IF_NONE_MATCH']
        inm = inm.split(/\s*,+\s*/).map { |i| i.tr_s ?", '' }
        return resp unless (obj.digests.values.map(&:to_s) & inm).empty?
      end

      # check if-modified-since
      if ims = hdrs['HTTP_IF_MODIFIED_SINCE']
        ims.gsub!(/^([^,]*(?:,[^,]*)?)(?:\s*,.*)?$/, "\\1")
        if ims = Time.httpdate(ims).getgm rescue nil
          return resp if ims > lm
        end
      end
    end

    # set headers
    type = obj.type.dup # note the type comes out frozen
    type << ";charset=#{obj.charset}" if obj.charset
    resp.set_header 'Content-Type',     type
    resp.set_header 'Content-Encoding', obj.encoding if obj.encoding
    resp.set_header 'Content-Length',   obj.size.to_s

    # return 200
    resp.status = 200
    resp.body   = ct

    resp
  end

  DISPATCH[:stats][:GET] = -> uri, query, hdrs, body = nil do
    stats = store.stats

    pri = store.primary

    sections = stats.label_struct.map do |slug, values|
      label, values = values
      { [
         { [label] => :h2 },
         { values.map { |val, count|
            q = serialize_query({ slug => val})
            href = "#{pri}/?#{q}"

            { { [ { [val] => :code }, ': ',
              { [count] => :var }] => :a, href: href } => :li } } => :ul },
        ] => :section }
    end

    doc = XML::Mixup.xhtml_stub(
      title: 'Content-Addressable Storage Stats',
      content: [
        { [
          { ['Statistics'] => :h2 },
          { [
            { ['Created:'] => :dt },
            { [stats.ctime] => :dd },
            { ['Last modified:'] => :dt },
            { [stats.mtime] => :dd },
            { ['Total objects:'] => :dt },
            { [stats.objects] => :dd },
            { ['Deleted records:'] => :dt },
            { [stats.deleted] => :dd },
            { ['Repository size:'] => :dt },
            { [stats.human_size] => :dd } ] => :dl },
          ] => :section } ] + sections,
    ).document

    [200, [['Content-Type', 'application/xhtml+xml;charset=utf-8']], doc.to_xml]
  end

  THEAD = { [
    'Digest', 'Size', 'Media Type', 'Language', 'Character Set', 'Encoding',
    'Added to Store', 'Modified', 'Metadata Changed', 'Deleted?'].map do |x|
      { [x] => :th }
    end => :thead }.freeze

  LINKS = {
    first: ['First', ?[],
    prev:  ['Previous', ?-],
    next:  ['Next', ?=],
    last:  ['Last', ?]],
  }

  DISPATCH[:collection][:GET] = -> uri, query, hdrs, body = nil do
    # parse query components
    query = coerce_query query

    # if there is no boundary parameter we redirect so there is
    unless query[:boundary]
      q = uri.query || ''
      q << ?& unless q.empty?
      q << serialize_query({ boundary: [1, 100] })
      uri.query = q
      return [307, [['Location', uri.to_s]], []]
    end

    # now we sanitize the boundary
    bound = query.delete :boundary
    bound[0] = 1   unless bound[0] and bound[0] >= 1
    bound[1] = 100 unless bound[1] and bound[1] >= bound[0]
    offset = bound[0] - 1
    limit  = bound[1] - offset

    # okay everything else in here should be legit
    tr  = store.list(**query)
    len = tr.length
    tr  = tr.slice(offset, limit).map do |obj|
      td = [{ [{ [obj[store.primary].hexdigest] => :a,
        href: obj[store.primary].b64digest }] => :td }] +
        %i[type size language charset encoding
        ctime mtime ptime dtime].map do |p|
        v = obj.send(p)
        v = v.is_a?(Time) ? v.getgm.iso8601 : v.to_s
        { [v] => :td }
      end
      { td => :tr }
    end

    links = {
      # first is 1 .. limit, only active if offset > 0
      first: offset > 0 ? [1, limit] : nil,
      # prev is also only active if offset > 0 but will subtract by limit
      prev:  offset > 0 ? [
        (x = (offset - limit >= 0 ? offset - limit : 0)) + 1, x + limit] : nil,
      # next is only active if len > offset + page
      next:  (offset + limit) < len ?
        [offset + limit + 1, 2 * limit + offset] : nil,
      # last is also only active if len > offset + page and
      last:  (offset + limit) < len ?
        [(x = (len.to_f / limit).floor * limit) + 1, x + limit] : nil,
    }.map do |rel, bound|
      link = if bound
               lab, ak = LINKS[rel]
               # href = uri.dup
               q = uri_query uri
               q = serialize_query(q.merge({ boundary: bound }))
               # href.query = q
               { [lab] => :a, rel: rel,
                accesskey: ak, href: "?#{q}" }
             else
               LINKS[rel].first
             end
      { [link] => :li }
    end


    doc = XML::Mixup.xhtml_stub(
      title: "Listing stored objects",
      content: { [ { [ { links => :ul } ] => :caption },
        THEAD, { tr => :tbody } ] => :table }
    ).document

    [200, [['Content-Type', 'application/xhtml+xml']], doc.to_xml]
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
    # warn env.inspect
    # do surgery to request scheme
    env['HTTPS'] = 'on' if
      env['REQUEST_SCHEME'] and env['REQUEST_SCHEME'].downcase == 'https'

    req   = Rack::Request.new env
    uri   = URI(req.base_url) + env['REQUEST_URI']
    path  = uri.path.gsub(/^\/+\.well-known\/+ni\/+/, '').split(/\/+/, -1)
    query = uri_query uri # XXX req.GET is worthless
    body  = req.body

    # dispatch type
    disp = nil
    if path.empty?
      disp = :stats
    elsif store.algorithms.include?(algo = path.first.to_sym)
      if slug = path[1]
        if slug.empty?
          disp = :collection
        elsif !/^[0-9A-Za-z_-]+$/.match?(slug)
          return [404, [], []]
        else
          # determine if we have a whole digest or just part of one
          algo = query[:algorithm] = path.first.to_sym

          query[:digest] = slug

          if /^[0-9A-Za-z_-]+$/.match?(slug) and
              slug.length == (DIGESTS[algo] * 4/3.0).ceil
            disp = :object
          elsif /^[0-9A-Fa-f]+$/.match?(slug) and
              slug.length == DIGESTS[algo] * 2
            query[:radix] = 16

            disp = :object
          else
            disp = :partial
          end
        end
      else
        # redirect 307
        newuri = req.base_url + "/.well-known/ni/#{algo}/"
        return [307, [['Location', newuri.to_s]], []]
      end
    elsif path.first == post_raw
      disp = :raw
    elsif path.first == post_form
      # 415 unsupported media type
      # XXX EXPLAIN THIS
      return [415, [], []] unless
        req.get_header('Content-Type') == 'multipart/form-data'

      # 409 conflict
      # XXX EXPLAIN THIS
      return Rack::Response[409, [], []] unless
        req.POST.values.any? { |f|
        f.is_a? Rack::Multipart::UploadedFile }

      # XXX here is where we would set the date from the
      # multipart header but rack doesn't have a way of doing this

      disp = :raw
    else
      # 404 again  
      return [404, [], []]
    end

    if methods = DISPATCH[disp]
      m = (req.request_method == 'HEAD' ? 'GET' : req.request_method).to_sym
      if func = methods[m]
        begin
          resp = instance_exec uri.dup, query, req.env.dup, body, &func
          resp = Rack::Response[*resp] if resp.is_a? Array
        rescue Exception => e
          warn "wah #{e}"
          return [500, [], []]
        end

        resp.body = [] if req.request_method == 'HEAD'

        return resp.to_a
      else
        return [405, [], []]
      end
    else
      return [404, [], []]
    end
  end
end
