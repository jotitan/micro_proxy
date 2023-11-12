package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const flushMinutes = 1

type Monitoring struct {
	// key is kind
	metrics             map[string]Metric
	chanel              chan string
	urlMonitoringServer string
}

type Metric []int

func (metric Metric) add() {
	metric[time.Now().Minute()]++
}

func (m Monitoring) sendMetrics() {
	t := time.Now().Add(-1 * time.Minute)
	date := t.Minute()
	request := MetricsRequest{Name: "Proxy", Metrics: make(map[string]MetricPoint)}
	for kind, metric := range m.metrics {
		if metric[date] > 0 {
			request.Metrics[kind] = MetricPoint{Timestamp: t.Unix(), Value: float32(metric[date])}
			metric[date] = 0
		}
	}
	if len(request.Metrics) > 0 {
		data, _ := json.Marshal(request)
		buffer := bytes.NewBuffer(data)
		http.Post(fmt.Sprintf("%s/metric", m.urlMonitoringServer), "application/json", buffer)
	}
}

type MetricsRequest struct {
	Metrics map[string]MetricPoint
	Name    string
}

type MetricPoint struct {
	Timestamp int64
	Value     float32
}

func (m Monitoring) runFlushing() {
	go func() {
		ticker := time.NewTicker(time.Minute * flushMinutes)
		for {
			<-ticker.C
			m.sendMetrics()
		}
	}()
}

func (m Monitoring) runReceiveEvents() {
	go func() {
		for {
			kind := <-m.chanel
			m.saveMetric(kind)
		}
	}()
}

func (m Monitoring) addMetric(kind string) {
	m.chanel <- kind
}

func (m Monitoring) saveMetric(kind string) {
	if m.urlMonitoringServer == "" {
		return
	}
	metric, exist := m.metrics[kind]
	if !exist {
		metric = make([]int, 60)
		m.metrics[kind] = metric
	}
	metric.add()
}

func NewMonitoring(url string) Monitoring {
	m := Monitoring{
		chanel:              make(chan string, 10),
		metrics:             make(map[string]Metric),
		urlMonitoringServer: url,
	}
	m.runFlushing()
	m.runReceiveEvents()
	return m
}
