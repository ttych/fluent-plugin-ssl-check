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
* timeout: timeout for ssl check execution (5sec)
* log_events: emit log format (true)
* metric_events: emit metric format (false)
* event_prefix: metric event prefix for extra dimension
* timestamp_format: iso, epochmillis timestamp format (iso)

If no port is specified with host, default port is 443.

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
