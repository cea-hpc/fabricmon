// Copyright 2017-20 Daniel Swarbrick. All rights reserved.
// SPDX-License-Identifier: GPL-3.0-or-later

// cgo wrapper around libibumad / libibnetdiscover.
// Note: Due to the usual permissions on /dev/infiniband/umad*, this will probably need to be
// executed as root.

// Package fabricmon is an InfiniBand fabric monitor daemon.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/dswarbrick/fabricmon/config"
	"github.com/dswarbrick/fabricmon/infiniband"
	"github.com/dswarbrick/fabricmon/version"
	"github.com/dswarbrick/fabricmon/writer"
	"github.com/dswarbrick/fabricmon/writer/forcegraph"
	"github.com/dswarbrick/fabricmon/writer/influxdb"
	"github.com/dswarbrick/fabricmon/writer/prometheus_exporter"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// router duplicates a Fabric struct received via channel and outputs it to multiple receiver
// channels.
func router(input chan infiniband.Fabric, writers []writer.FabricWriter) {
	outputs := make([]chan infiniband.Fabric, len(writers))

	// Create output channels for workers, and start worker goroutine
	for i, w := range writers {
		outputs[i] = make(chan infiniband.Fabric)
		go w.Receiver(outputs[i])
	}

	for fabric := range input {
		for _, c := range outputs {
			c <- fabric
		}
	}

	// Close output channels
	for _, c := range outputs {
		close(c)
	}

	slog.Debug("Router input channel closed. Exiting function.")
}

func main() {
	var (
		configFile = kingpin.Flag("config", "Path to config file.").Default("fabricmon.yml").File()
		daemonize  = kingpin.Flag("daemonize", "Run forever, fetching counters periodically.").Default("true").Bool()
	)

	kingpin.Parse()

	conf, err := config.ReadConfig(*configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	(*configFile).Close()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: conf.Logging.LogLevel})))

	// Initialise umad library (also required in order to run under ibsim).
	if infiniband.UmadInit() < 0 {
		slog.Error("Error initialising umad library. Exiting.")
		os.Exit(1)
	}

	slog.Info("FabricMon " + version.Info())
	hcas := infiniband.GetCAs()

	if len(hcas) == 0 {
		slog.Error("No HCAs found in system. Exiting.")
		os.Exit(1)
	}

	hcas_info_metric := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fabricmon_hca_info",
		Help: "Informations about discovered HCAs",
	},
		[]string{"ca", "type", "ports", "firmware_version", "hardware_version", "node_guid", "system_guid"})

	for _, hca := range hcas {
		info := hca.HCAInfo()
		hcas_info_metric.WithLabelValues(
			info["ca"],
			info["type"],
			info["ports"],
			info["firmware_version"],
			info["hardware_version"],
			info["node_guid"],
			info["system-guid"],
		).Set(1)
	}

	// Channel to signal goroutines that we are shutting down.
	shutdownChan := make(chan bool)

	// Setup signal handler to catch SIGINT, SIGTERM.
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, unix.SIGINT, unix.SIGTERM)
	go func() {
		s := <-sigChan
		slog.Debug("shutting down due to signal", "signal", s)
		close(shutdownChan)
	}()

	// Initialize empty slice to hold writers
	writers := make([]writer.FabricWriter, 0)

	if conf.Topology.Enabled {
		writers = append(writers, &forcegraph.ForceGraphWriter{OutputDir: conf.Topology.OutputDir})
	}

	if conf.PrometheusExporter.Enabled {
		w := prometheus_exporter.NewPrometheusWriter(conf.PrometheusExporter)
		writers = append(writers, w)
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(conf.PrometheusExporter.ListenAddr, nil)
	}

	// First sweep.
	for _, hca := range hcas {
		hca.NetDiscover(nil, conf.Mkey, conf.ResetThreshold)
	}

	if *daemonize {
		for _, c := range conf.InfluxDB {
			w := influxdb.NewInfluxDBWriter(c)
			writers = append(writers, w)
		}

		for _, c := range conf.InfluxDB {
			w := influxdb.NewInfluxDBWriter(c)
			writers = append(writers, w)
		}

		// FIXME: Move this outside of daemonize if-block
		splitter := make(chan infiniband.Fabric)
		go router(splitter, writers)

		ticker := time.NewTicker(time.Duration(conf.PollInterval))
		defer ticker.Stop()

	Loop:
		// Loop indefinitely, scanning fabrics every tick.
		for {
			select {
			case <-ticker.C:
				for _, hca := range hcas {
					hca.NetDiscover(splitter, conf.Mkey, conf.ResetThreshold)
				}
			case <-shutdownChan:
				slog.Debug("shutdown received in polling loop")
				break Loop
			}
		}

		close(splitter)
	}

	slog.Debug("cleaning up")

	// Free associated memory from pointers in umad_ca_t.ports
	for _, hca := range hcas {
		hca.Release()
	}

	infiniband.UmadDone()
}
