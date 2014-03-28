package main

import (
    "io/ioutil"
    "fmt"
    "encoding/binary"
    "bytes"
    "strconv"
)

const (
    ORDERING_IDENTICAL = 0xa1b2c3d4
    ORDERING_SWAPPED = 0xd4c3b2a1
)

type GlobalHeader struct {
    magic_number uint32
    version_major uint16
    version_minor uint16
    thiszone int32
    sigfigs uint32
    snaplen uint32
    network uint32
}

type PacketHeader struct {
    ts_sec uint32
    ts_usec uint32
    incl_len uint32
    orig_len uint32
}

type Packet struct {
    header PacketHeader
    data []byte
}

func magic_number(chunk []byte) (magic_number uint32) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &magic_number)
    if err != nil {
        panic("Reading magic number failed")
    }

    if magic_number == ORDERING_SWAPPED || magic_number == ORDERING_IDENTICAL {
        return
    }

    panic("Bad magic number")
}

func version_major(chunk []byte) (version_major uint16) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &version_major)
    if err != nil {
        panic("Reading major version failed")
    }

    return
}

func version_minor(chunk []byte) (version_minor uint16) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &version_minor)
    if err != nil {
        panic("Reading minor version failed")
    }

    return
}

func thiszone(chunk []byte) (thiszone int32) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &thiszone)
    if err != nil {
        panic("Reading time zone correction failed")
    }

    if thiszone != 0 {
        fmt.Println("Note: thiszone (time zone correction) not 0")
    }

    return
}

func sigfigs(chunk []byte) (sigfigs uint32) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &sigfigs)
    if err != nil {
        panic("Reading time zone correction failed")
    }

    if sigfigs != 0 {
        fmt.Println("Note: sigfigs (time stamp accuracy) not 0")
    }

    return
}

func snaplen(chunk []byte) (snaplen uint32) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &snaplen)
    if err != nil {
        panic("Reading snapshot length failed")
    }

    return
}

func network(chunk []byte) (network uint32) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &network)
    if err != nil {
        panic("Reading snapshot length failed")
    }

    return
}

func ts_sec(chunk []byte) (ts_sec uint32) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &ts_sec)
    if err != nil {
        panic("Reading packet timestamp failed")
    }

    return
}

func ts_usec(chunk []byte) (ts_usec uint32) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &ts_usec)
    if err != nil {
        panic("Reading packet timestamp microseconds failed")
    }

    return
}

func incl_len(chunk []byte) (incl_len uint32) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &incl_len)
    if err != nil {
        panic("Reading packet capture length failed")
    }

    return
}

func orig_len(chunk []byte) (orig_len uint32) {
    buf := bytes.NewReader(chunk)
    err := binary.Read(buf, binary.LittleEndian, &orig_len)
    if err != nil {
        panic("Reading packet capture original length failed")
    }

    return
}

func global_next() {
    chunk_size := global_header_layout[global_index]

    if global_index > 0 {
        global_begin = global_end
    }

    global_end += chunk_size
    global_index ++
}

func packet_next() {
    chunk_size := packet_header_layout[packet_index]

    if packet_index > 0 {
        packet_begin = packet_end
    }

    packet_end += chunk_size
    packet_index ++
}

var (
    global_header_layout = []int{4, 2, 2, 4, 4, 4, 4}
    packet_header_layout = []int{4, 4, 4, 4}
    global_begin, global_end, global_index int = 0, 0, 0
    packet_begin, packet_end, packet_index int = 0, 0, 0
)

func main() {
    net, _ := ioutil.ReadFile("net.pcap")

    header := GlobalHeader{}
    global_next()

    header.magic_number = magic_number(net[global_begin:global_end])
    global_next()

    header.version_major = version_major(net[global_begin:global_end])
    global_next()

    header.version_minor = version_minor(net[global_begin:global_end])
    global_next()

    header.thiszone = thiszone(net[global_begin:global_end])
    global_next()

    header.sigfigs = sigfigs(net[global_begin:global_end])
    global_next()

    header.snaplen = snaplen(net[global_begin:global_end])
    global_next()

    header.network = network(net[global_begin:global_end])

    packet_begin = global_end
    packet_end = global_end

    var records []Packet
    i := 0
    for packet_end < len(net) {
        packet := Packet{}
        packet_next()

        packet.header.ts_sec = ts_sec(net[packet_begin:packet_end])
        packet_next()

        packet.header.ts_usec = ts_usec(net[packet_begin:packet_end])
        packet_next()

        packet.header.incl_len = incl_len(net[packet_begin:packet_end])
        packet_next()

        packet.header.orig_len = orig_len(net[packet_begin:packet_end])

        if packet.header.incl_len > header.snaplen {
            panic("Encountered packet bigger than snapshot length specified")
        }

        if packet.header.incl_len > packet.header.orig_len {
            panic("Encountered packet with larger included length than original packet")
        }

        data_end := packet_end + int(packet.header.incl_len)
        packet.data = net[packet_end:data_end]

        packet_end += int(packet.header.incl_len)

        records = append(records, packet)

        packet_index = 0
        i ++
    }

    fmt.Printf("Parsed %s records.\n\n", strconv.Itoa(i))
}
