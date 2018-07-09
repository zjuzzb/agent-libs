package main

import (
	"bufio"
	"bytes"
	"cointerface/draiosproto"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"io"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: decode_proto [-msgtype=<msgtype>]\n")
	fmt.Fprintf(os.Stderr, "   <msgtype>: type of message to decode\n")
	flag.PrintDefaults()
	os.Exit(1)
}

func mymain() int {
	flag.Usage = usage
	msgTypePtr := flag.String("msgtype", "falco_baseline", "message type to decode buffer as")

	flag.Parse()

	bio := bufio.NewReader(os.Stdin)

	for {
		line, err := bio.ReadBytes('\n')
		if err == io.EOF {
			return 0
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Can not read line: %v\n", err)
			return 1
		}

		line = bytes.TrimPrefix(line, []byte("0x"))
		line = bytes.TrimSuffix(line, []byte("\r\n"))
		line = bytes.TrimSuffix(line, []byte("\n"))

		if(*msgTypePtr == "falco_baseline") {
			bin := make([]byte, hex.DecodedLen(len(line)))
			len, err := hex.Decode(bin, line); if err != nil {
				fmt.Fprintf(os.Stderr, "Can not hex decode line after %v bytes: %v\n", len, err)
				return 1
			}
			bl := &draiosproto.FalcoBaseline{}
			err = proto.Unmarshal(bin, bl); if err != nil {
				fmt.Fprintf(os.Stderr, "Can not parse proto message from line: %v\n", err)
				return 1
			}

			pretty, err := json.MarshalIndent(*bl, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Can not pretty-print struct: %v\n", err)
				return 1
			}

			fmt.Fprintf(os.Stdout, "%v\n", string(pretty))
		}
	}

	return 0
}

func main() {
	os.Exit(mymain())
}
