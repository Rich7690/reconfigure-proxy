package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oracle/oci-go-sdk/v50/common"
	"github.com/oracle/oci-go-sdk/v50/common/auth"
	"github.com/oracle/oci-go-sdk/v50/core"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var reconfigureBindAddr *string = flag.String("p", "0.0.0.0:8080", "private reconfigure address")

var configBucket []byte = []byte("config")
var whitelistIp []byte = []byte("whitelist_ip")
var cachedIP string

func whitelistFunc(oci core.VirtualNetworkClient) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.Header.Get("X-Real-Ip")
		parsed := net.ParseIP(ip)

		if parsed == nil {
			http.Error(w, "Invalid ip: "+ip, http.StatusBadRequest)
			return
		}
		err := whitelistOCI(r.Context(), oci, parsed.String())

		if err != nil {
			log.Println("error whitelisting ip: ", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte(parsed.String()))
	}
}

func privateReconfigureWeb() {

	provider := common.DefaultConfigProvider()

	if os.Getenv("LOCAL") == "" {
		var err error
		provider, err = auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			panic(err)
		}
	}

	oci, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)

	if err != nil {
		panic(err)
	}

	inFlightGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "in_flight_requests",
		Help: "A gauge of requests currently being served by the wrapped handler.",
	})

	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "api_requests_total",
			Help: "A counter for requests to the wrapped handler.",
		},
		[]string{"code", "method"},
	)

	// duration is partitioned by the HTTP method and handler. It uses custom
	// buckets based on the expected request duration.
	duration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "request_duration_seconds",
			Help:    "A histogram of latencies for requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"handler", "method"},
	)

	prometheus.MustRegister(inFlightGauge, counter, duration)
	whitelistChain := promhttp.InstrumentHandlerInFlight(inFlightGauge,
		promhttp.InstrumentHandlerDuration(duration.MustCurryWith(prometheus.Labels{"handler": "whitelist"}),
			promhttp.InstrumentHandlerCounter(counter,
				http.HandlerFunc(whitelistFunc(oci)),
			),
		),
	)

	r := mux.NewRouter()
	r.Methods(http.MethodGet).Path("/health").HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Methods(http.MethodPost).Path("/whitelist").Handler(whitelistChain)
	r.Methods(http.MethodGet).Path("/metrics").Handler(promhttp.Handler())

	// Create a CA certificate pool and add cert.pem to it
	/*caCert, err := os.ReadFile("./ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.BuildNameToCertificate()*/

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr: *reconfigureBindAddr,
		//TLSConfig:   tlsConfig,
		Handler:     http.TimeoutHandler(r, 10*time.Second, ""),
		ReadTimeout: 10 * time.Second,
	}

	// EXPLAIN: We perform TLS termination and client verification on the LB, but this is here in case we want it here
	// err = server.ListenAndServeTLS("./server.crt", "./server.key")
	err = server.ListenAndServe()

	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()
	fmt.Printf("Listening: %v\n", *reconfigureBindAddr)

	_, cancel := context.WithCancel(context.Background())
	notChan := make(chan os.Signal, 2)

	signal.Notify(notChan, syscall.SIGINT, os.Interrupt)

	go privateReconfigureWeb()

	<-notChan
	cancel()
	log.Println("Exiting")
}

func whitelistOCI(ctx context.Context, oci core.VirtualNetworkClient, ip string) error {
	if ip == "" {
		return errors.New("failed to resolve addresses")
	}

	log.Printf("%v", ip)

	if os.Getenv("LOCAL") != "" {
		return nil
	}

	policy := common.DefaultRetryPolicy()

	resp, err := oci.ListNetworkSecurityGroupSecurityRules(ctx, core.ListNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId: common.String(os.Getenv("NSG_ID")),
		RequestMetadata:        common.RequestMetadata{RetryPolicy: &policy},
		Direction:              core.ListNetworkSecurityGroupSecurityRulesDirectionIngress,
	})

	if err != nil {
		return err
	}

	portMap := map[int]bool{80: true, 443: true, 7000: true}
	var updatedRules = make([]core.UpdateSecurityRuleDetails, 0)

	changed := false
	for i := range resp.Items {
		item := resp.Items[i]
		if item.TcpOptions != nil && portMap[*item.TcpOptions.DestinationPortRange.Min] {
			newSource := common.String(ip + "/32")
			if *newSource != *item.Source {
				changed = true
				cachedIP = *item.Source
			}
			item.Source = newSource
			updatedRules = append(updatedRules, core.UpdateSecurityRuleDetails{
				Direction:       core.UpdateSecurityRuleDetailsDirectionEnum(item.Direction),
				Id:              item.Id,
				Protocol:        item.Protocol,
				Description:     item.Description,
				Destination:     item.Destination,
				DestinationType: core.UpdateSecurityRuleDetailsDestinationTypeEnum(item.DestinationType),
				IsStateless:     item.IsStateless,
				Source:          item.Source,
				SourceType:      core.UpdateSecurityRuleDetailsSourceTypeEnum(item.SourceType),
				TcpOptions:      item.TcpOptions,
			})
		}
	}
	if !changed {
		log.Println("No change in security rules")
		return nil
	} else {
		log.Println("Updating ip from ", cachedIP, " to ", ip)
	}

	_, err = oci.UpdateNetworkSecurityGroupSecurityRules(ctx, core.UpdateNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId: common.String(os.Getenv("NSG_ID")),
		UpdateNetworkSecurityGroupSecurityRulesDetails: core.UpdateNetworkSecurityGroupSecurityRulesDetails{
			SecurityRules: updatedRules,
		},
	})
	return err
}
