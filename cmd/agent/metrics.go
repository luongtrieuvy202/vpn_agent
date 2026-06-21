package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vpnplatform/agent/trafficcontrol"
	"github.com/vpnplatform/agent/wireguard"
)

var metricUsagePushTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "wg_agent_usage_push_total",
		Help: "Usage report push attempts by result (success|error|http_error).",
	},
	[]string{"result"},
)

// agentCollector reports live state on each scrape.
type agentCollector struct {
	wg *wireguard.Manager
	tc *trafficcontrol.Manager // may be nil

	peers   *prometheus.Desc
	ifaceUp *prometheus.Desc
	tcRules *prometheus.Desc
	tcUp    *prometheus.Desc
}

func registerMetrics(wg *wireguard.Manager, tc *trafficcontrol.Manager) {
	prometheus.MustRegister(metricUsagePushTotal)
	prometheus.MustRegister(&agentCollector{
		wg:      wg,
		tc:      tc,
		peers:   prometheus.NewDesc("wg_agent_peers", "WireGuard peers on this node.", nil, nil),
		ifaceUp: prometheus.NewDesc("wg_agent_interface_up", "1 if the WireGuard interface exists.", nil, nil),
		tcRules: prometheus.NewDesc("wg_agent_tc_rules", "Active traffic-control rules.", nil, nil),
		tcUp:    prometheus.NewDesc("wg_agent_tc_up", "1 if traffic control is enabled and initialized.", nil, nil),
	})
}

func (c *agentCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.peers
	ch <- c.ifaceUp
	ch <- c.tcRules
	ch <- c.tcUp
}

func (c *agentCollector) Collect(ch chan<- prometheus.Metric) {
	ifaceUp := 0.0
	peerCount := 0.0
	if c.wg.InterfaceExists() {
		ifaceUp = 1.0
		if peers, err := c.wg.ListPeers(); err == nil {
			peerCount = float64(len(peers))
		}
	}
	ch <- prometheus.MustNewConstMetric(c.ifaceUp, prometheus.GaugeValue, ifaceUp)
	ch <- prometheus.MustNewConstMetric(c.peers, prometheus.GaugeValue, peerCount)

	tcUp := 0.0
	tcRules := 0.0
	if c.tc != nil {
		tcUp = 1.0
		tcRules = float64(len(c.tc.ListRules()))
	}
	ch <- prometheus.MustNewConstMetric(c.tcUp, prometheus.GaugeValue, tcUp)
	ch <- prometheus.MustNewConstMetric(c.tcRules, prometheus.GaugeValue, tcRules)
}
