// Copyright 2017-18 Daniel Swarbrick. All rights reserved.
// Use of this source code is governed by a GPL license that can be found in the LICENSE file.
//
// TODO: Add support for specifying retention policy.

// Package influxdb implements the InfluxDBWriter, which writes InfiniBand performance counters to
// one or more configured InfluxDB backends.
package prometheus_exporter

import (
	"strconv"
	"fmt"
	
	log "github.com/sirupsen/logrus"

	"github.com/dswarbrick/fabricmon/config"
	"github.com/dswarbrick/fabricmon/infiniband"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus"
)

type PrometheusWriter struct {
	config config.PrometheusExporterConf
	hca_port_vec *prometheus.GaugeVec
	hca_port_speed *prometheus.GaugeVec
	hca_port_width *prometheus.GaugeVec
}

func NewPrometheusWriter(config config.PrometheusExporterConf) *PrometheusWriter {
	hca_port_vec := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fabricmon_port_counter",
		Help: "Informations about discovered HCAs",
	},
		[]string{"src_host", "src_hca", "src_hca_port", "guid", "node_desc", "node_port", "counter", "device_id", "vendor_id"})
	hca_port_speed := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fabricmon_port_speed",
		Help: "Informations about discovered HCAs",
	},
		[]string{"src_host", "src_hca", "src_hca_port", "guid", "node_desc", "node_port", "device_id", "vendor_id"})
	hca_port_width := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fabricmon_port_width",
		Help: "Informations about discovered HCAs",
	},
		[]string{"src_host", "src_hca", "src_hca_port", "guid", "node_desc", "node_port", "device_id", "vendor_id"})
	return &PrometheusWriter{config: config, hca_port_vec: hca_port_vec, hca_port_speed: hca_port_speed, hca_port_width: hca_port_width}
}

// TODO: Rename this to something more descriptive (and which is not so easily confused with method
// receivers).
func (w *PrometheusWriter) Receiver(input chan infiniband.Fabric) {
	// Loop indefinitely until input chan closed.

	for fabric := range input {
		err := w.makeBatch(fabric)
		log.WithFields(log.Fields{
			"hca":    fabric.CAName,
			"port":   fabric.SourcePort,
		}).Debugf("Prometheus exporter metrics update")
		if err != nil {
			log.Error(err)
		}
	}

	log.Debug("PrometheusWriter input channel closed.")
}

func (w *PrometheusWriter) makeBatch(fabric infiniband.Fabric) (error) {
	tags := map[string]string{
		"host":     fabric.Hostname,
		"hca":      fabric.CAName,
		"src_port": strconv.Itoa(fabric.SourcePort),
	}

	for _, node := range fabric.Nodes {
		if node.NodeType != infiniband.IB_NODE_SWITCH {
			continue
		}

		tags["guid"] = fmt.Sprintf("%016x", node.GUID)
		tags["node_desc"] = node.NodeDesc
		tags["device_id"] = fmt.Sprintf("%016x", node.DeviceID)
		tags["vendor_id"] = fmt.Sprintf("%016x", node.VendorID)
		
		
		for portNum, port := range node.Ports {
			tags["port"] = strconv.Itoa(portNum)

			for counter, value := range port.Counters {
				switch value.(type) {
				case uint32:
					tags["counter"] = infiniband.StdCounterMap[counter].Name
					w.hca_port_vec.WithLabelValues(tags["host"], tags["hca"], tags["src_port"], tags["guid"], tags["node_desc"], tags["port"], tags["counter"], tags["device_id"], tags["vendor_id"]).Set(float64(value.(uint32)))
				case uint64:
					tags["counter"] = infiniband.ExtCounterMap[counter].Name
					w.hca_port_vec.WithLabelValues(tags["host"], tags["hca"], tags["src_port"], tags["guid"], tags["node_desc"], tags["port"], tags["counter"], tags["device_id"], tags["vendor_id"]).Set(float64(value.(uint64)))
				default:
					continue
				}

			}
		}
	}

	return nil
}
