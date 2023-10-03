# fluent-plugin-ssl-check

[Fluentd](https://fluentd.org/) input plugin to check ssl service.


## plugins

### in - ssl_check

Poll ssl service, to report status.

Example:

``` conf
<source>
  @type ssl_check
  tag ssl_check

  hosts my-service.com:4443

  interval 600

  ca_path /my/ca_dir/
  ca_file /my/ca_file
</source>
```

Options are:
* tag: Tag to emit events on
* hosts: list of <host>:<port> to check
* interval: check every X seconds
* ca_path: directory that contains CA files
* ca_file: specify a CA file directly
* sni: want the sni support (true)
* verify_mode: none or peer
* cert: client cert for ssl connection
* key: client key associated to client cert for ssl connection
* timeout: timeout for ssl check execution (5sec)
* log_events: emit log format (true)
* metric_events: emit metric format (false)
* event_prefix: metric event prefix for extra dimension
* timestamp_format: iso, epochmillis timestamp format (iso)

If no port is specified with host, default port is 443.


## output examples

### log output example

``` json
{
    "timestamp": "2023-10-03T09:59:41.580+02:00",
    "status": 1,
    "host": "www.google.fr",
    "port": 443,
    "ssl_version": "TLSv1.2",
    "ssl_dn": "/CN=*.google.fr",
    "ssl_not_after": "2023-11-27T08:25:08.000Z",
    "expire_in_days": 55,
    "serial": "4e79dbb13c6b57b309780da2d1edbda4"
}
```

### metric output example

``` json
{
    "timestamp": "2023-10-03T10:06:21.417+02:00",
    "metric_name": "ssl_status",
    "metric_value": 1,
    "host": "www.google.fr",
    "port": 443,
    "ssl_dn": "/CN=*.google.fr",
    "ssl_version": "TLSv1.2",
    "ssl_not_after": "2023-11-27T08:25:08.000Z",
    "serial": "4e79dbb13c6b57b309780da2d1edbda4"
}

{
    "timestamp": "2023-10-03T10:06:21.417+02:00",
    "metric_name": "ssl_expirency",
    "metric_value": 55,
    "host": "www.google.fr",
    "port": 443,
    "ssl_dn": "/CN=*.google.fr",
    "serial": "4e79dbb13c6b57b309780da2d1edbda4"
}
```


## Installation

Manual install, by executing:

    $ gem install fluent-plugin-ssl-check

Add to Gemfile with:

    $ bundle add fluent-plugin-ssl-check


## Compatibility

plugin in 1.x.x will work with:
- ruby >= 2.7.7
- td-agent >= 4.0.0


## Copyright

* Copyright(c) 2023- Thomas Tych
* License
  * Apache License, Version 2.0
