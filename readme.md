# go-pcap

Parse pcap files in pure Go. No libpcap dependency. This is a personal/learning project.

## Motivation

I've had occassion to use pcaps with increasing frequency, and I wanted to familiarize myself with the format. What better way to do so than to write a parser from scratch? Working on this particular format also afforded an opportunity to refresh myself on the many layers of encapsulation at the network level.

And, I don't write as many things that parse at this layer as I'd like. This was a decent opportunity to work on my encoding skills (hex, binary, et al.), though the format is not complex.

In addition, I am enjoying working in Go and wanted an excuse to write more of it. Also my GitHub profile is sad and dusty since I commit to GitHub Enterprise nowadays.

## Don't Use This

Use [gopcap](https://github.com/Lukasa/gopcap) by @Lukasa instead. It was not written in a little over an hour, and it parses down several OSI layers. It is also a proper library, and it has premium features like tests.

## Caveats

Before reading the caveats, please read and understand the prior topic.

- Recognizes swapped ordering in the magic number; does absolutely nothing about it
- Struct heirarchy is not optimal
- Oh, lord, the byte movement funtions `global_next()` and `packet_next()`
- Lots of duplication in the methods to fetch bytes into integers
- Some general style issues as a result of writing it much too quickly; don't worry, I probably know it sucks
