// Copyright 2017-18 Daniel Swarbrick. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.

package infiniband

// #cgo CFLAGS: -I/usr/include/infiniband
// #include <mad.h>
import "C"

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

var portStates = [...]string{
	"No state change", // Valid only on Set() port state
	"Down",            // Includes failed links
	"Initialize",
	"Armed",
	"Active",
}

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