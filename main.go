/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"aws-sigv4-proxy/handler"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/gorilla/mux"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	debug                  = kingpin.Flag("verbose", "Enable additional logging, implies all the log-* options").Short('v').Bool()
	logFailedResponse      = kingpin.Flag("log-failed-requests", "Log 4xx and 5xx response body").Bool()
	logSinging             = kingpin.Flag("log-signing-process", "Log sigv4 signing process").Bool()
	port                   = kingpin.Flag("port", "Port to serve http on").Default(":8080").String()
	strip                  = kingpin.Flag("strip", "Headers to strip from incoming request").Short('s').Strings()
	roleArn                = kingpin.Flag("role-arn", "Amazon Resource Name (ARN) of the role to assume").String()
	signingNameOverride    = kingpin.Flag("name", "AWS Service to sign for").String()
	hostOverride           = kingpin.Flag("host", "Host to proxy to").String()
	regionOverride         = kingpin.Flag("region", "AWS region to sign for").String()
	disableSSLVerification = kingpin.Flag("no-verify-ssl", "Disable peer SSL certificate validation").Bool()
	retries                = kingpin.Flag("retries", "number of retries on failed requests").Default("5").Short('r').Int()
)

type awsLoggerAdapter struct {
}

// Log implements aws.Logger.Log
func (awsLoggerAdapter) Log(args ...interface{}) {
	log.Info(args...)
}
func init() {
	prometheus.Register(totalRequests)
}
func main() {
	kingpin.Parse()

	log.SetLevel(log.InfoLevel)
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	sessionConfig := aws.Config{}
	if v := os.Getenv("AWS_STS_REGIONAL_ENDPOINTS"); len(v) == 0 {
		sessionConfig.STSRegionalEndpoint = endpoints.RegionalSTSEndpoint
	}

	session, err := session.NewSession(&sessionConfig)
	if err != nil {
		log.Fatal(err)
	}

	if *regionOverride != "" {
		session.Config.Region = regionOverride
	}

	// For STS regional endpoint to be effective config's region must be set.
	if *session.Config.Region == "" {
		defaultRegion := "us-east-1"
		session.Config.Region = &defaultRegion
	}

	if *disableSSLVerification {
		log.Warn("Peer SSL Certificate validation is DISABLED")
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	var credentials *credentials.Credentials
	if *roleArn != "" {
		credentials = stscreds.NewCredentials(session, *roleArn, func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = roleSessionName()
		})
	} else {
		credentials = session.Config.Credentials
	}

	signer := v4.NewSigner(credentials, func(s *v4.Signer) {
		if *logSinging || *debug {
			s.Logger = awsLoggerAdapter{}
			s.Debug = aws.LogDebugWithSigning
		}
	})

	var client *http.Client
	if *retries > 0 {
		client = makeRetryable()
	} else {
		client = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	log.WithFields(log.Fields{"StripHeaders": *strip}).Infof("Stripping headers %s", *strip)
	log.WithFields(log.Fields{"port": *port}).Infof("Listening on %s", *port)

	router := mux.NewRouter()
	router.Use(prometheusMiddleware)
	router.Path("/metrics").Handler(promhttp.Handler())
	router.PathPrefix("/").Handler(&handler.Handler{
		ProxyClient: &handler.ProxyClient{
			Signer:              signer,
			Client:              client,
			StripRequestHeaders: *strip,
			SigningNameOverride: *signingNameOverride,
			HostOverride:        *hostOverride,
			RegionOverride:      *regionOverride,
			LogFailedRequest:    *logFailedResponse,
		},
	})

	log.Fatal(
		http.ListenAndServe(*port, router),
	)
}

func roleSessionName() string {
	suffix, err := os.Hostname()

	if err != nil {
		now := time.Now().Unix()
		suffix = strconv.FormatInt(now, 10)
	}
	return "aws-sigv4-proxy-" + suffix
}

// setup the retryablehttp client
func makeRetryable() *http.Client {
	rclient := retryablehttp.NewClient()
	rclient.RetryMax = *retries
	rclient.RetryWaitMin = 100 * time.Millisecond
	rclient.RetryWaitMax = 1000 * time.Millisecond
	rclient.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	// retry attempts are logged at debug so don't need to add that. May want to add something
	// to prometheus here so leaving the example commented out.
	//
	// rclient.RequestLogHook = func(_ retryablehttp.Logger, _ *http.Request, attempt int) {
	// 	// no need to log if there's no retry
	// 	if attempt > 0 {
	// 		log.WithFields(log.Fields{
	// 			"attempt": attempt,
	// 		}).Debug("Retrying request")
	// 	}
	// }
	throttleErrorRe := regexp.MustCompile(`<ThrottlingException`)
	rclient.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		b, _ := ioutil.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusBadRequest && throttleErrorRe.MatchString(string(b)) {
			return true, nil
		}
		// don't propagate other errors
		shouldRetry, _ := retryablehttp.DefaultRetryPolicy(ctx, resp, err)
		// reset the body
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		return shouldRetry, nil
	}
	return rclient.StandardClient()
}

// add prometheus metrics
var totalRequests = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Number of get requests.",
	},
	[]string{"path"},
)

func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := mux.CurrentRoute(r)
		path, _ := route.GetPathTemplate()
		//rw := http.NewResponseWriter()
		next.ServeHTTP(w, r)

		totalRequests.WithLabelValues(path).Inc()
	})

}
