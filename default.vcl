vcl 4.0;

import std;
import directors;

# Default backend definition. Set this to point to your content server.
backend server1 {
    .host = "127.0.0.1";
    .port = "9876";
    .max_connections = 300; # That's it

    /*.probe = {
        # We prefer to only do a HEAD /
        .request =
            "HEAD / HTTP/1.1"
            "Host: localhost"
            "Connection: close"
            "User-Agent: Varnish Health Probe";

        .interval  = 5s; # check the health of each backend every 5 seconds
        .timeout   = 1s; # timing out after 1 second.
        .window    = 5;  # If 3 out of the last 5 polls succeeded the backend is considered healthy, otherwise it will be marked as sick
        .threshold = 3;
    }*/

    .first_byte_timeout     = 300s;   # How long to wait before we receive a first byte from our backend?
    .connect_timeout        = 5s;     # How long to wait for a backend connection?
    .between_bytes_timeout  = 2s;     # How long to wait between bytes received from our backend?
}

# Only allow purging from specific IPs
acl purge {
    "localhost";
    "127.0.0.1";
    "::1";
}

sub vcl_init {
  # Called when VCL is loaded, before any requests pass through it.
  # Typically used to initialize VMODs.

  new vdir = directors.round_robin();
  vdir.add_backend(server1);
  # vdir.add_backend(server...);
  # vdir.add_backend(servern);
}

# There are 3 possible behaviors of purging.

# Regex purging
# Treat the request URL as a regular expression.
sub purge_regex {
    ban("obj.http.X-Req-URL ~ " + req.url + " && obj.http.X-Req-Host == " + req.http.host);
}

# Exact purging
# Use the exact request URL (including any query params)
sub purge_exact {
    ban("obj.http.X-Req-URL == " + req.url + " && obj.http.X-Req-Host == " + req.http.host);
}

# Page purging (default)
# Use the exact request URL, but ignore any query params
sub purge_page {
    set req.url = regsub(req.url, "\?.*$", "");
    ban("obj.http.X-Req-URL-Base == " + req.url + " && obj.http.X-Req-Host == " + req.http.host);
}

sub vcl_recv {
    # Called at the beginning of a request, after the complete request has been received and parsed.
    # Its purpose is to decide whether or not to serve the request, how to do it, and, if applicable,
    # which backend to use.
    # also used to modify the request

    set req.backend_hint = vdir.backend(); # send all traffic to the vdir director

    # Normalize the header, remove the port (in case you're testing this on various TCP ports)
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

    # Remove the proxy header (see https://httpoxy.org/#mitigate-varnish)
    unset req.http.proxy;

    # Normalize the query arguments
    # Disabled for now. This breaks css and js loaders and some plugins in Wordpress
    #set req.url = std.querysort(req.url);

    # Allow purging
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
        # Use std.ip if behind TLS terminator and/or load-balancer
        #if (!std.ip(req.http.X-forwarded-for, "0.0.0.0") ~ purge) { # purge is the ACL defined at the begining
            # Not from an allowed IP? Then die with an error.
            return (synth(405, "This IP is not allowed to send PURGE requests."));
        }

        # If you got this stage (and didn't error out above), purge the cached result
        if (req.http.X-Purge-Method) {
            if (req.http.X-Purge-Method ~ "(?i)regex") {
                call purge_regex;
            } elsif (req.http.X-Purge-Method ~ "(?i)exact") {
                call purge_exact;
            } else {
                call purge_page;
            }
        } else {
            # No X-Purge-Method header was specified.
            # Do our best to figure out which one they want.
            if (req.url ~ "\.\*" || req.url ~ "^\^" || req.url ~ "\$$" || req.url ~ "\\[.?*+^$|()]") {
                call purge_regex;
            } elsif (req.url ~ "\?") {
                call purge_exact;
            } else {
                call purge_page;
            }
        }

        return(synth(200, "Purged."));
    }

    # Only deal with "normal" types
    if (req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" &&
        req.method != "POST" &&
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "PATCH" &&
        req.method != "DELETE") {
        /* Non-RFC2616 or CONNECT which is weird. */
        return (pipe);
    }

    # Implementing websocket support (https://www.varnish-cache.org/docs/4.0/users-guide/vcl-example-websockets.html)
    if (req.http.Upgrade ~ "(?i)websocket") {
        return (pipe);
    }

    # Only cache GET or HEAD requests. This makes sure the POST requests are always passed.
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Some generic URL manipulation, useful for all templates that follow
    # First remove the Google Analytics added parameters, useless for our backend
    if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
        set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
        set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
        set req.url = regsub(req.url, "\?&", "?");
        set req.url = regsub(req.url, "\?$", "");
    }

    # Strip hash, server doesn't need it.
    if (req.url ~ "\#") {
        set req.url = regsub(req.url, "\#.*$", "");
    }

    # Strip a trailing ? if it exists
    if (req.url ~ "\?$") {
        set req.url = regsub(req.url, "\?$", "");
    }

    # Some generic cookie manipulation, useful for all templates that follow
    # Remove the "has_js" cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");

    # Remove any Google Analytics based cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "_ga=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "_gat=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmctr=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmcmd.=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmccn.=[^;]+(; )?", "");
	#set req.http.Cookie = regsuball(req.http.Cookie, "_.+?=[^;]+(; )?", "");
	#set req.http.Cookie = regsuball(req.http.Cookie, "__.+?=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "(^|;\s*)(_[_a-z]+|has_js)=[^;]*", "");

	# Remove Google Analytics Dashboard for Wordpress cookies
	set req.http.Cookie = regsuball(req.http.Cookie, "gadwp.+?=[^;]+(; )?", "");

    # Remove DoubleClick offensive cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "__gads=[^;]+(; )?", "");

    # Remove the Quant Capital cookies (added by some plugin, all __qca)
    set req.http.Cookie = regsuball(req.http.Cookie, "__qc.=[^;]+(; )?", "");

    # Remove the AddThis cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "__atuv.=[^;]+(; )?", "");

    # Remove several Wordpress-specific cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-1=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-time-\d+=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "wordpress_test_cookie=[^;]+(; )?", "");

    # Remove cookies from the jetpack plugin if not logged in and not on /wp-admin or /wp-login.php
    if (!req.url ~ "^/wp-(login|admin)" || !req.url ~ "^/veilig-inloggen" || !req.http.Cookie ~ "wp-postpass_|wordpress_logged_in_|PHPSESSID") {
		set req.http.Cookie = regsuball(req.http.Cookie, "jetpack.+?=[^;]+(; )?", "");
    }

    # Remove a ";" prefix in the cookie if present
    set req.http.Cookie = regsuball(req.http.Cookie, "^;\s*", "");

    # Are there cookies left with only spaces or that are empty?
    if (req.http.cookie ~ "^\s*$") {
        unset req.http.cookie;
    }

	## ignore any other cookies
	#unset req.http.Cookie;

    if (req.http.Cache-Control ~ "(?i)no-cache") {
        if (client.ip ~ purge) {
        # Use std.ip if behind TLS terminator and/or load-balancer
        #if (std.ip(req.http.X-forwarded-for, "0.0.0.0") ~ purge) {
            # Ignore requests via proxy caches and badly behaved crawlers
            # like msnbot that send no-cache with every request.
            if (! (req.http.Via || req.http.User-Agent ~ "(?i)bot" || req.http.X-Purge)) {
                #set req.hash_always_miss = true; # Doesn't seems to refresh the object in the cache
                return(purge); # Couple this with restart in vcl_purge and X-Purge header to avoid loops
            }
        }
    }

	# Alllow serving from the cache even if the client has requested that the document not be served from the cache. This might result in stale content being served.
	unset req.http.Cache-Control;
	unset req.http.Pragma;

    # Large static files are delivered directly to the end-user without
    # waiting for Varnish to fully read the file first.
    # Varnish 4 fully supports Streaming, so set do_stream in vcl_backend_response()
    if (req.url ~ "^[^?]*\.(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;
        return (pass);
    }

    # Remove all cookies for static files
    # A valid discussion could be held on this line: do you really need to cache static files that don't cause load? Only if you have memory left.
    # Sure, there's disk I/O, but chances are your OS will already have these files in their buffers (thus memory).
    # Before you blindly enable this, have a read here: https://ma.ttias.be/stop-caching-static-files/
    if (req.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;
        return (pass);
    }

    # Send Surrogate-Capability headers to announce ESI support to backend
    set req.http.Surrogate-Capability = "key=ESI/1.0";

    set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;

    # admin users always miss the cache
    if (req.url ~ "^/wp-(login|admin)" || req.url ~ "^/veilig-inloggen" || req.http.Cookie ~ "wp-postpass_|wordpress_logged_in_|comment_author|PHPSESSID") {
        return (pass);
    }

    # Don't cache wordpress-specific items
    if (req.http.Cookie ~ "wordpress_" || req.http.Cookie ~ "comment_") {
        return (pass);
    }

    if (req.url ~ "(edit\.php)") {
        return(pass);
    }

    if (req.url ~ "/wp-cron.php" || req.url ~ "preview=true" || req.url ~ "xmlrpc.php") {
        return (pass);
    }

     # Don't cache WooCommerce
    if (req.url ~ "/(cart|my-account|checkout|addons|/?add-to-cart=)") {
        return (pass);
    }

    # Don't cache searchs
    if (req.url ~ "\?s=") {
        return (pass);
    }

  	# Did not cache HTTP authentication and HTTP Cookie
    if (req.http.Authorization) {
  		# Not cacheable by default
  		return (pass);
  	}

	# If there's still a cookie left, just to be sure, do not cache
	if (req.http.Cookie) {
		return (pass);
	}

    return (hash);
}


sub vcl_pipe {
  # Called upon entering pipe mode.
  # In this mode, the request is passed on to the backend, and any further data from both the client
  # and backend is passed on unaltered until either end closes the connection. Basically, Varnish will
  # degrade into a simple TCP proxy, shuffling bytes back and forth. For a connection in pipe mode,
  # no other VCL subroutine will ever get called after vcl_pipe.

  # Note that only the first request to the backend will have
  # X-Forwarded-For set.  If you use X-Forwarded-For and want to
  # have it set for all requests, make sure to have:
  # set bereq.http.connection = "close";
  # here.  It is not set by default as it might break some broken web
  # applications, like IIS with NTLM authentication.

  set bereq.http.Connection = "Close";

  # Implementing websocket support (https://www.varnish-cache.org/docs/4.0/users-guide/vcl-example-websockets.html)
  if (req.http.upgrade) {
    set bereq.http.upgrade = req.http.upgrade;
  }

  return (pipe);
}

sub vcl_pass {
  # Called upon entering pass mode. In this mode, the request is passed on to the backend, and the
  # backend's response is passed on to the client, but is not entered into the cache. Subsequent
  # requests submitted over the same client connection are handled normally.

  # return (pass);
}

# The data on which the hashing will take place
sub vcl_hash {
  # Called after vcl_recv to create a hash value for the request. This is used as a key
  # to look up the object in Varnish.

  hash_data(req.url);

  if (req.http.host) {
    hash_data(req.http.host);
  } else {
    hash_data(server.ip);
  }

  # hash cookies for requests that have them
  if (req.http.Cookie) {
    hash_data(req.http.Cookie);
  }
}

sub vcl_hit {
  # Called when a cache lookup is successful.

  if (obj.ttl >= 0s) {
    # A pure unadultered hit, deliver it
    return (deliver);
  }

  # https://www.varnish-cache.org/docs/trunk/users-guide/vcl-grace.html
  # When several clients are requesting the same page Varnish will send one request to the backend and place the others on hold while fetching one copy from the backend. In some products this is called request coalescing and Varnish does this automatically.
  # If you are serving thousands of hits per second the queue of waiting requests can get huge. There are two potential problems - one is a thundering herd problem - suddenly releasing a thousand threads to serve content might send the load sky high. Secondly - nobody likes to wait. To deal with this we can instruct Varnish to keep the objects in cache beyond their TTL and to serve the waiting requests somewhat stale content.

# if (!std.healthy(req.backend_hint) && (obj.ttl + obj.grace > 0s)) {
#   return (deliver);
# } else {
#   return (miss);
# }

  # We have no fresh fish. Lets look at the stale ones.
  if (std.healthy(req.backend_hint)) {
    # Backend is healthy. Limit age to 10s.
    if (obj.ttl + 10s > 0s) {
      #set req.http.grace = "normal(limited)";
      return (deliver);
    } else {
      # No candidate for grace. Fetch a fresh object.
      return(miss);
    }
  } else {
    # backend is sick - use full grace
    if (obj.ttl + obj.grace > 0s) {
      #set req.http.grace = "full";
      return (deliver);
    } else {
      # no graced object.
      return (miss);
    }
  }

  # fetch & deliver once we get the result
  return (miss); # Dead code, keep as a safeguard
}

sub vcl_miss {
  # Called after a cache lookup if the requested document was not found in the cache. Its purpose
  # is to decide whether or not to attempt to retrieve the document from the backend, and which
  # backend to use.

  return (fetch);
}


# Handle the HTTP request coming from our backend
sub vcl_backend_response {
    set beresp.http.X-Req-Host = bereq.http.host;
    set beresp.http.X-Req-URL = bereq.url;
    set beresp.http.X-Req-URL-Base = regsub(bereq.url, "\?.*$", "");
  # Called after the response headers has been successfully retrieved from the backend.

  # Pause ESI request and remove Surrogate-Control header
  if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
    unset beresp.http.Surrogate-Control;
    set beresp.do_esi = true;
  }

  # Enable cache for all static files
  # The same argument as the static caches from above: monitor your cache size, if you get data nuked out of it, consider giving up the static file cache.
  # Before you blindly enable this, have a read here: https://ma.ttias.be/stop-caching-static-files/
  if (bereq.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
    unset beresp.http.set-cookie;
	set beresp.uncacheable = true;
  }

  # Large static files are delivered directly to the end-user without
  # waiting for Varnish to fully read the file first.
  # Varnish 4 fully supports Streaming, so use streaming here to avoid locking.
  if (bereq.url ~ "^[^?]*\.(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") {
    unset beresp.http.set-cookie;
    set beresp.do_stream = true;  # Check memory usage it'll grow in fetch_chunksize blocks (128k by default) if the backend doesn't send a Content-Length header, so only enable it for big objects
	set beresp.uncacheable = true;
  }

  if (bereq.url ~ "wp-(login|admin)" || bereg.url ~ "veilig-inloggen" || bereq.url ~ "preview=true") {
    set beresp.uncacheable = true;
    #set beresp.ttl = 120s;
  }

  # Sometimes, a 301 or 302 redirect formed via Apache's mod_rewrite can mess with the HTTP port that is being passed along.
  # This often happens with simple rewrite rules in a scenario where Varnish runs on :80 and Apache on :8080 on the same box.
  # A redirect can then often redirect the end-user to a URL on :8080, where it should be :80.
  # This may need finetuning on your setup.
  #
  # To prevent accidental replace, we only filter the 301/302 redirects for now.
  if (beresp.status == 301 || beresp.status == 302) {
    set beresp.http.Location = regsub(beresp.http.Location, ":[0-9]+", "");
  }

  # Set 2min cache if unset for static files
  if (beresp.ttl <= 0s || beresp.http.Set-Cookie || beresp.http.Vary == "*") {
    #set beresp.ttl = 120s; # Important, you shouldn't rely on this, SET YOUR HEADERS in the backend
    set beresp.uncacheable = true;
    set beresp.http.X-Cacheable = "NO:Not Cacheable";
    return (deliver);
  }

  # Don't cache 50x responses
  if (beresp.status == 500 || beresp.status == 502 || beresp.status == 503 || beresp.status == 504) {
    return (abandon);
  }

  if (beresp.http.Cache-Control ~ "private") {
    set beresp.uncacheable = true;
    set beresp.http.X-Cacheable = "NO:Cache-Control=private";
    return (deliver);
  }

  #if (req.http.Cookie ~ "wp-postpass_|wordpress_logged_in_|comment_author|PHPSESSID") {
  #  set beresp.uncacheable = true;
  #  set beresp.http.X-Cacheable = "NO:Got Session";
  #  return (deliver);
  #}

  # Default TTL
  set beresp.ttl = 24h;

  # Allow stale content, in case the backend goes down.
  # make Varnish keep all objects for 6 hours beyond their TTL
  set beresp.grace = 6h;

  # Object was cacheable
  set beresp.http.X-Cacheable = "YES";

  return (deliver);
}

# The routine when we deliver the HTTP request to the user
# Last chance to modify headers that are sent to the client
sub vcl_deliver {
  # Called before a cached object is delivered to the client.
    unset resp.http.X-Req-Host;
    unset resp.http.X-Req-URL;
    unset resp.http.X-Req-URL-Base;

  if (obj.hits > 0) { # Add debug header to see if it's a HIT/MISS and the number of hits, disable when not needed
    set resp.http.X-Cache = "HIT";
  } else {
    set resp.http.X-Cache = "MISS";
  }

  # Please note that obj.hits behaviour changed in 4.0, now it counts per objecthead, not per object
  # and obj.hits may not be reset in some cases where bans are in use. See bug 1492 for details.
  # So take hits with a grain of salt
  set resp.http.X-Cache-Hits = obj.hits;

  # Remove some headers: PHP version
  unset resp.http.X-Powered-By;

  # Remove some headers: Apache version & OS
  unset resp.http.Server;
  unset resp.http.X-Drupal-Cache;
  #unset resp.http.X-Varnish;
  unset resp.http.Via;
  unset resp.http.Link;
  unset resp.http.X-Generator;

  return (deliver);
}

sub vcl_purge {
  # Only handle actual PURGE HTTP methods, everything else is discarded
  if (req.method != "PURGE") {
    # restart request
    set req.http.X-Purge = "Yes";
    return(restart);
  }
}

sub vcl_synth {
  if (resp.status == 720) {
    # We use this special error status 720 to force redirects with 301 (permanent) redirects
    # To use this, call the following from anywhere in vcl_recv: return (synth(720, "http://host/new.html"));
    set resp.http.Location = resp.reason;
    set resp.status = 301;
    return (deliver);
  } elseif (resp.status == 721) {
    # And we use error status 721 to force redirects with a 302 (temporary) redirect
    # To use this, call the following from anywhere in vcl_recv: return (synth(720, "http://host/new.html"));
    set resp.http.Location = resp.reason;
    set resp.status = 302;
    return (deliver);
  }

  return (deliver);
}


sub vcl_fini {
  # Called when VCL is discarded only after all requests have exited the VCL.
  # Typically used to clean up VMODs.

  return (ok);
}
