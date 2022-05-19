package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/oracle/oci-go-sdk/v50/common"
	"github.com/oracle/oci-go-sdk/v50/common/auth"
	"github.com/oracle/oci-go-sdk/v50/core"

	"github.com/gorilla/mux"
	bolt "go.etcd.io/bbolt"
)

var localAddr *string = flag.String("l", "0.0.0.0:9999", "local address")
var remoteAddr *string = flag.String("r", "localhost:8443", "remote address")
var reconfigureBindAddr *string = flag.String("p", "0.0.0.0:8080", "private reconfigure address")

var configBucket []byte = []byte("config")
var whitelistIp []byte = []byte("whitelist_ip")

func whitelistFunc(client *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.Header.Get("X-Real-Ip")
		parsed := net.ParseIP(ip)

		if parsed == nil {
			http.Error(w, "Invalid ip: "+ip, http.StatusBadRequest)
			return
		}

		var cachedIP string
		err := client.View(func(tx *bolt.Tx) error {
			cached := tx.Bucket(configBucket).Get(whitelistIp)
			cachedIP = string(cached)
			return nil
		})

		if err != nil {
			log.Println("error getting cached ip: ", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if cachedIP != parsed.String() {
			log.Println("Updating ip from ", cachedIP, " to ", ip)
			cachedIP = ip

			err := whitelistOCI(r.Context(), parsed.String())

			if err != nil {
				log.Println("error whitelisting ip: ", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			err = client.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(configBucket).Put(whitelistIp, []byte(parsed.String()))
			})

			if err != nil {
				log.Println("error saving cached ip: ", err.Error())
			}
		}

		w.Write([]byte(parsed.String()))
	}
}

func setRemoteIpFunc(client *bolt.DB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.Header.Get("X-Real-Ip")
		parsed := net.ParseIP(ip)

		if parsed == nil {
			http.Error(w, "Invalid ip: "+ip, http.StatusBadRequest)
			return
		}
		newAddr := parsed.String() + ":8443"
		remoteAddr = &newAddr

		_, _ = w.Write([]byte(parsed.String()))
	}
}

func privateReconfigureWeb() {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	client, err := bolt.Open(path.Join(dir, "proxy.db"), 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		panic(err)
	}

	err = client.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(configBucket)
		return err
	})

	if err != nil {
		panic(err)
	}

	r := mux.NewRouter()
	r.Methods(http.MethodGet).Path("/health").HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Methods(http.MethodPost).Path("/whitelist").HandlerFunc(whitelistFunc(client))
	r.Methods(http.MethodPost).Path("/setRemoteIp").HandlerFunc(setRemoteIpFunc(client))

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
	fmt.Printf("Listening: %v\nProxying: %v\n\n", *localAddr, *remoteAddr)

	_, cancel := context.WithCancel(context.Background())
	notChan := make(chan os.Signal, 2)

	signal.Notify(notChan, syscall.SIGINT, os.Interrupt)

	go privateReconfigureWeb()

	go func() {
		listener, err := net.Listen("tcp", *localAddr)
		if err != nil {
			panic(err)
		}
		for {
			conn, err := listener.Accept()
			log.Println("New connection", conn.RemoteAddr())
			if err != nil {
				log.Println("error accepting connection", err)
				continue
			}
			go func() {
				defer conn.Close()
				conn2, err := net.Dial("tcp", *remoteAddr)
				if err != nil {
					log.Println("error dialing remote addr", err)
					return
				}
				defer conn2.Close()
				closer := make(chan struct{}, 2)
				go copyD(closer, conn2, conn)
				go copyD(closer, conn, conn2)
				<-closer
				log.Println("Connection complete", conn.RemoteAddr())
			}()
		}
	}()

	<-notChan
	cancel()
	log.Println("Exiting")
}

func copyD(closer chan struct{}, dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src)
	closer <- struct{}{} // connection is closed, send signal to stop proxy
}

func whitelistOCI(ctx context.Context, ip string) error {
	if ip == "" {
		return errors.New("failed to resolve addresses")
	}

	log.Printf("%v", ip)

	if os.Getenv("LOCAL") != "" {
		return nil
	}

	provider := common.DefaultConfigProvider()

	if os.Getenv("LOCAL") == "" {
		var err error
		provider, err = auth.InstancePrincipalConfigurationProvider()
		if err != nil {
			return err
		}
	}

	oci, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)

	if err != nil {
		return err
	}

	policy := common.DefaultRetryPolicy()

	resp, err := oci.ListNetworkSecurityGroupSecurityRules(ctx, core.ListNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId: common.String(os.Getenv("NSG_ID")),
		RequestMetadata:        common.RequestMetadata{RetryPolicy: &policy},
	})

	if err != nil {
		return err
	}

	portMap := map[int]bool{80: true, 443: true, 7000: true}
	var updatedRules = make([]core.UpdateSecurityRuleDetails, 0)

	for i := range resp.Items {
		item := resp.Items[i]
		if item.TcpOptions != nil && portMap[*item.TcpOptions.DestinationPortRange.Min] {
			item.Source = common.String(ip + "/32")
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

	_, err = oci.UpdateNetworkSecurityGroupSecurityRules(ctx, core.UpdateNetworkSecurityGroupSecurityRulesRequest{
		NetworkSecurityGroupId: common.String(os.Getenv("NSG_ID")),
		UpdateNetworkSecurityGroupSecurityRulesDetails: core.UpdateNetworkSecurityGroupSecurityRulesDetails{
			SecurityRules: updatedRules,
		},
	})
	return err
}
