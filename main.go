// package main

// import (
// 	"bytes"
// 	"encoding/hex"
// 	"fmt"
// 	"log"
// 	"os"

// 	"github.com/google/gopacket"
// 	"github.com/google/gopacket/layers"
// 	"github.com/google/gopacket/pcap"
// )

// func main() {
// 	if len(os.Args) < 2 {
// 		fmt.Println("Please provide a pcap file to read")
// 		os.Exit(1)
// 	}

// 	handle, err := pcap.OpenOffline(os.Args[1])
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer handle.Close()

// 	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
// 	for packet := range packetSource.Packets() {
// 		tcpLayer := packet.Layer(layers.LayerTypeTCP)
// 		if tcpLayer != nil {
// 			tcpPacket, _ := tcpLayer.(*layers.TCP)

// 			encodedString := hex.EncodeToString(tcpPacket.Payload)
// 			if encodedString != "" && encodedString[18:22] == "6384" {
// 				fmt.Print("LDAP Filter: ")
// 				var cont bytes.Buffer
// 				for _, el := range tcpPacket.Payload[62:] {
// 					if el >= 48 && el <= 122 {
// 						cont.WriteString(fmt.Sprintf("%s", byte(el)))
// 						//fmt.Printf("|%02X|", byte(el))
// 						//fmt.Print(string(el))
// 					} else {
// 						cont.WriteString(fmt.Sprintf("|%02X|", byte(el)))
// 						fmt.Printf("|%02X|", byte(el))
// 					}
// 				}
// 				fmt.Println()

// 				rule := fmt.Sprintf("alert tcp any any -> any [389,636,3268,3269] (msg:\"LDAP seach request\"; flow:to_server,established; content:\"|63|\"; content:\"|04|\"; distance:0; content:\"DC=\"; nocase; distance:0; content:\"|0A 01 02|\"; distance:0; content:\"%s\"; nocase; distance:0; threshold:type both,track by_src,count 1,seconds 60; sid:1000001; rev:1;)", cont.String())

// 				fmt.Println(rule)
// 				fmt.Println()
// 			}
// 		}
// 	}
// }

package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt" // Import the fmt package to print messages to the console.
	"io"
	"log" // Import the log package to log errors to the console.
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/google/gopacket"        // Import the gopacket package to decode packets.
	"github.com/google/gopacket/layers" // Import the layers package to access the various network layers.
	"github.com/google/gopacket/pcap"   // Import the pcap package to capture packets.
)

func main() {

	// Check if file argument is provided
	if len(os.Args) < 2 {
		log.Fatalln("Please provide a pcap file to read and tcp payload offset")
	}

	offset, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalln("Set tcp payload offset as integer")
	}
	parsePcapFile(offset, os.Args[2]) //START MAIN FUNC
	getMD5sum(os.Args[2])
	TsharkGetLdapFilteand(os.Args[2])

}

func parsePcapFile(tcpOffset int, pcapName string) {

	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(pcapName)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		// Print the packet details
		//fmt.Println(packet.String())

		// Extract and print the Ethernet layer
		// ethLayer := packet.Layer(layers.LayerTypeEthernet)
		// if ethLayer != nil {
		// 	ethPacket, _ := ethLayer.(*layers.Ethernet)
		// 	fmt.Println("Ethernet source MAC address:", ethPacket.SrcMAC)
		// 	fmt.Println("Ethernet destination MAC address:", ethPacket.DstMAC)
		// }

		// Extract and print the IP layer
		// ipLayer := packet.Layer(layers.LayerTypeIPv4)
		// if ipLayer != nil {
		// 	ipPacket, _ := ipLayer.(*layers.IPv4)
		// 	fmt.Println("IP source address:", ipPacket.SrcIP)
		// 	fmt.Println("IP destination address:", ipPacket.DstIP)
		// }

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcpPacket, _ := tcpLayer.(*layers.TCP)

			//Using just to get hex to filter ldap search requests
			encodedString := hex.EncodeToString(tcpPacket.Payload)

			//[TODO]Replace with regexp that matches rule content
			//Filter to get only ldap_search_requests
			if encodedString != "" && len(encodedString) > 22 {
				if encodedString[18:22] == "6384" {
					//PRINT HEX PAYLOAD
					fmt.Println(hex.Dump(tcpPacket.Payload))
					//fmt.Println(hex.Dump(tcpPacket.Payload[tcpOffset:]))
					parseLDAPFilter(tcpPacket.Payload[tcpOffset:])
				}

			}

		}
	}
}

func parseLDAPFilter(data []byte) string {

	strOut := ""

	for i, b := range data {
		if i >= 2 {
			if b >= 32 && b <= 126 { // ASCII range
				if data[i-1] < 32 || data[i-1] > 126 { // Check if the previous byte is not ASCII and print 2 hex values

					s := fmt.Sprintf("|%02x %02x|%s", data[i-2], data[i-1], string(b))
					strOut = strOut + s
				} else {

					strOut = strOut + string(b)
				}
			} else if data[i-1] >= 32 && data[i-1] <= 126 { //If not ASCII and nex

				strOut = strOut + "*"
			}
		}
	}

	a := strings.Split(strOut, "*")
	//fmt.Println(strOut)
	res := ""
	for _, el := range a {
		res = res + fmt.Sprintf("content:\"%s\";nocase;distance:0;within:100; \\\n", el)
	}

	fmt.Printf("alert tcp any any -> any [389,636,3268,3269] (msg:\"LDAP seach request\"; flow:to_server,established;\\\ncontent:\"|63|\"; content:\"|04|\"; distance:0; content:\"DC=\"; nocase; distance:0; content:\"|0A 01 02|\"; distance:0;\\\n%sthreshold:type both,track by_src,count 1,seconds 60; sid:1000001; rev:1;)\n", res)
	fmt.Println()
	return fmt.Sprintf("alert tcp any any -> any [389,636,3268,3269] (msg:\"LDAP seach request\"; flow:to_server,established;\\\ncontent:\"|63|\"; content:\"|04|\"; distance:0; content:\"DC=\"; nocase; distance:0; content:\"|0A 01 02|\"; distance:0;\\\n%sthreshold:type both,track by_src,count 1,seconds 60; sid:1000001; rev:1;)\n", res)

}

func TsharkGetLdapFilteand(pcapFile string) {

	tsharkFilters := []string{"-r", pcapFile, "-Y", "ldap.protocolOp == 3", "-T", "fields", "-e", "text"}

	cmdTshark := exec.Command("tshark", tsharkFilters...)

	cmdTshark.Stderr = os.Stderr

	out, err := cmdTshark.Output()

	if err != nil {
		fmt.Println("Err startig tshark", err)
	} else {
		fmt.Println("LDAP FILTERS:", string(out))

	}
}

func getMD5sum(filename string) {

	file, err := os.Open(filename)
	if err != nil {
		log.Panicln("[!] Cant  open pcap file to get md5sum")
		return
	}
	defer file.Close()

	h := md5.New()
	if _, err := io.Copy(h, file); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("MD5sum: %x\n", h.Sum(nil))

}
