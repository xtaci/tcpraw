# tcpraw

[![GoDoc][1]][2] [![MIT licensed][3]][4] [![Go Report Card][5]][6]

[1]: https://godoc.org/github.com/xtaci/tcpraw?status.svg
[2]: https://godoc.org/github.com/xtaci/tcpraw
[3]: https://img.shields.io/badge/license-MIT-blue.svg
[4]: LICENSE
[5]: https://goreportcard.com/badge/github.com/xtaci/tcpraw
[6]: https://goreportcard.com/report/github.com/xtaci/tcpraw


# Introduction

A packet-oriented connection by simulating tcp protocol

## Features

1. Support IPv4 and IPv6.

## Documentation

For complete documentation, see the associated [Godoc](https://godoc.org/github.com/xtaci/tcpraw).


## Tips
```
sudo tcpdump -v -n -i lo0 ip and 'ip[8]>0' and tcp and port 3457
```


## Status

GA
