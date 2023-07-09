# fluent-plugin-ssl-check

[Fluentd](https://fluentd.org/) input plugin to check ssl service.

## plugins

### in - ssl_check

Poll ssl service, to report status.

Example:

``` conf
<source>
  @type ssl_check
  tag ssh_check

  host my-service.com
  port 443

  interval 600

  ca_path /my/ca_dir/
  ca_file /my/ca_file
</source>
```

Options are:
* tag: Tag to emit events on
* host: host of the service to check
* port: port of the service to check
* interval: check every X seconds
* ca_path: directory that contains CA files
* ca_file: specify a CA file directly


## Installation

Manual install, by executing:

    $ gem install fluent-plugin-ssl-check

Add to Gemfile with:

    $ bundle add fluent-plugin-ssl-check


## Compatibility

plugin in 1.x.x will work with:
- ruby >= 2.4.10
- td-agent >= 3.8.1-0


## Copyright

* Copyright(c) 2023- Thomas Tych
* License
  * Apache License, Version 2.0
