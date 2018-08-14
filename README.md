[![Build Status](https://travis-ci.org/GeoffWilliams/puppet-windows_firewall.svg?branch=master)](https://travis-ci.org/GeoffWilliams/puppet-windows_firewall)
# windows_firewall

#### Table of Contents

1. [Description](#description)
1. [Usage - Configuration options and additional functionality](#usage)
1. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
1. [Limitations - OS compatibility, etc.](#limitations)
1. [Development - Guide for contributing to the module](#development)

## Description

Manage the windows firwall with Puppet (netsh)

## Usage
See reference and examples

## Reference
[generated documentation](https://rawgit.com/GeoffWilliams/puppet-windows_firewall/master/doc/index.html).

Reference documentation is generated directly from source code using [puppet-strings](https://github.com/puppetlabs/puppet-strings).  You may regenerate the documentation by running:

```shell
bundle exec puppet strings
```

## Limitations
* Not supported by Puppet, Inc.

## Development

PRs accepted :)

## Testing
This module supports testing using [PDQTest](https://github.com/declarativesystems/pdqtest).


Test can be executed with:

```
bundle install
make
```

See `.travis.yml` for a working CI example
