// Copyright 2017-18 Daniel Swarbrick. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
//
// TODO: Implement user-friendly display of link rate (see ib_types.h).

package infiniband

// #cgo CFLAGS: -I/usr/include/infiniband
// #include <mad.h>
// #include <umad.h>
import "C"

import (
	"fmt"
	"log"
	"unsafe"
)

const (
	PMA_TIMEOUT = 0
)

type Fabric struct {
	Hostname   string
	CAName     string
	SourcePort int
	Nodes      []Node
}

type Node struct {
	GUID     uint64
	NodeType int
	NodeDesc string
	VendorID uint16
	DeviceID uint16
	Ports    []Port
}

type Port struct {
	GUID       uint64
	RemoteGUID uint64
	Counters   map[uint32]interface{}
}

type Counter struct {
	Name   string
	Limit  uint64
	Select uint32 // CounterSelect (bits 0-15), CounterSelect2 (bits 16-23)
}

var (
	nnMap        NodeNameMap
	umad_ca_list = []C.umad_ca_t{}
)

// Standard (32-bit) counters and their display names.
// Counter lengths and field selects defined in IBTA spec v1.3, table 247 (PortCounters).
// Note: Standard data counters are absent from this map (e.g. PortXmitData, PortRcvData,
// PortXmitPkts, PortRcvPkts).
var StdCounterMap = map[uint32]Counter{
	C.IB_PC_ERR_SYM_F:        {"SymbolErrorCounter", 0xffff, 0x1},
	C.IB_PC_LINK_RECOVERS_F:  {"LinkErrorRecoveryCounter", 0xff, 0x2},
	C.IB_PC_LINK_DOWNED_F:    {"LinkDownedCounter", 0xff, 0x4},
	C.IB_PC_ERR_RCV_F:        {"PortRcvErrors", 0xffff, 0x8},
	C.IB_PC_ERR_PHYSRCV_F:    {"PortRcvRemotePhysicalErrors", 0xffff, 0x10},
	C.IB_PC_ERR_SWITCH_REL_F: {"PortRcvSwitchRelayErrors", 0xffff, 0x20},
	C.IB_PC_XMT_DISCARDS_F:   {"PortXmitDiscards", 0xffff, 0x40},
	C.IB_PC_ERR_XMTCONSTR_F:  {"PortXmitConstraintErrors", 0xff, 0x80},
	C.IB_PC_ERR_RCVCONSTR_F:  {"PortRcvConstraintErrors", 0xff, 0x100},
	C.IB_PC_ERR_LOCALINTEG_F: {"LocalLinkIntegrityErrors", 0xf, 0x200},
	C.IB_PC_ERR_EXCESS_OVR_F: {"ExcessiveBufferOverrunErrors", 0xf, 0x400},
	C.IB_PC_VL15_DROPPED_F:   {"VL15Dropped", 0xffff, 0x800},
	C.IB_PC_XMT_WAIT_F:       {"PortXmitWait", 0xffffffff, 0x10000}, // Requires cap mask IB_PM_PC_XMIT_WAIT_SUP
}

// Extended (64-bit) counters and their display names.
// Counter lengths and field selects defined in IBTA spec v1.3, table 260 (PortCountersExtended).
var ExtCounterMap = map[uint32]Counter{
	C.IB_PC_EXT_XMT_BYTES_F: {"PortXmitData", 0xffffffffffffffff, 0x1},
	C.IB_PC_EXT_RCV_BYTES_F: {"PortRcvData", 0xffffffffffffffff, 0x2},
	C.IB_PC_EXT_XMT_PKTS_F:  {"PortXmitPkts", 0xffffffffffffffff, 0x4},
	C.IB_PC_EXT_RCV_PKTS_F:  {"PortRcvPkts", 0xffffffffffffffff, 0x8},
	C.IB_PC_EXT_XMT_UPKTS_F: {"PortUnicastXmitPkts", 0xffffffffffffffff, 0x10},
	C.IB_PC_EXT_RCV_UPKTS_F: {"PortUnicastRcvPkts", 0xffffffffffffffff, 0x20},
	C.IB_PC_EXT_XMT_MPKTS_F: {"PortMulticastXmitPkts", 0xffffffffffffffff, 0x40},
	C.IB_PC_EXT_RCV_MPKTS_F: {"PortMulticastRcvPkts", 0xffffffffffffffff, 0x80},
}

// cf. PortInfo, table 155
var portStates = [...]string{
	"No state change", // Valid only on Set() port state
	"Down",            // Includes failed links
	"Initialize",
	"Armed",
	"Active",
}

// cf. PortInfo, table 155
var portPhysStates = [...]string{
	"No state change", // Valid only on Set() port state
	"Sleep",
	"Polling",
	"Disabled",
	"PortConfigurationTraining",
	"LinkUp",
	"LinkErrorRecovery",
	"Phy Test",
}

// cf. PortInfo, table 155
func LinkSpeedToStr(speed uint) string {
	switch speed {
	case 0:
		return "Extended speed"
	case 1:
		return "2.5 Gbps"
	case 2:
		return "5.0 Gbps"
	case 4:
		return "10.0 Gbps"
	default:
		return fmt.Sprintf("undefined (%d)", speed)
	}
}

// cf. PortInfo, table 155
func LinkWidthToStr(width uint) string {
	switch width {
	case 1:
		return "1X"
	case 2:
		return "4X"
	case 4:
		return "8X"
	case 8:
		return "12X"
	default:
		return fmt.Sprintf("undefined (%d)", width)
	}
}

func PortStateToStr(state uint) string {
	if state < uint(len(portStates)) {
		return portStates[state]
	}

	return fmt.Sprintf("undefined (%d)", state)
}

func PortPhysStateToStr(state uint) string {
	if state < uint(len(portPhysStates)) {
		return portPhysStates[state]
	}

	return fmt.Sprintf("undefined (%d)", state)
}

func init() {
	nnMap, _ = NewNodeNameMap()
}

func ScanCAs(caNames []string) {
	// umad_ca_t contains an array of pointers - associated memory must be freed with
	// umad_release_ca(umad_ca_t *ca)
	umad_ca_list = make([]C.umad_ca_t, len(caNames))

	for i, caName := range caNames {
		var ca C.umad_ca_t

		ca_name := C.CString(caName)
		C.umad_get_ca(ca_name, &ca)
		C.free(unsafe.Pointer(ca_name))

		log.Printf("Found CA %s (%s) with %d ports, firmware version: %s, hardware version: %s, "+
			"node GUID: %#016x, system GUID: %#016x\n",
			C.GoString(&ca.ca_name[0]), C.GoString(&ca.ca_type[0]), ca.numports,
			C.GoString(&ca.fw_ver[0]), C.GoString(&ca.hw_ver[0]),
			ntohll(uint64(ca.node_guid)), ntohll(uint64(ca.system_guid)))

		umad_ca_list[i] = ca
	}
}

func Sweep(c chan Fabric) {
	for _, ca := range umad_ca_list {
		caDiscoverFabric(ca, c)
	}
}

// UmadInit simply wraps the libibumad umad_init() function.
func UmadInit() int {
	return int(C.umad_init())
}

func UmadDone() {
	// Free associated memory from pointers in umad_ca_t.ports
	for _, ca := range umad_ca_list {
		if C.umad_release_ca(&ca) < 0 {
			log.Printf("ERROR: umad_release_ca %#v\n", ca)
		}
	}

	// NOTE: ibsim indicates that FabricMon is not "disconnecting" when it exits - resource leak?
	C.umad_done()
}
