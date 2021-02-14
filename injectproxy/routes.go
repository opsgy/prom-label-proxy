// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package injectproxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

type routes struct {
	upstream      *url.URL
	handler       http.Handler
	label         string
	labelLocation string
	mux           *http.ServeMux
	modifiers     map[string]func(*http.Response) error
}

func NewRoutes(upstream *url.URL, label string, labelLocation string) *routes {
	proxy := httputil.NewSingleHostReverseProxy(upstream)

	r := &routes{
		upstream:      upstream,
		handler:       proxy,
		label:         label,
		labelLocation: labelLocation,
	}
	mux := http.NewServeMux()
	mux.Handle("/federate", enforceMethods(r.federate, "GET"))
	mux.Handle("/api/v1/query", enforceMethods(r.query, "GET", "POST"))
	mux.Handle("/api/v1/query_range", enforceMethods(r.query, "GET", "POST"))
	mux.Handle("/api/v1/series", enforceMethods(r.series, "GET", "POST"))
	mux.Handle("/api/v1/labels", enforceMethods(r.noop, "GET"))
	mux.Handle("/api/v1/label/__name__/values", enforceMethods(r.noop, "GET"))
	mux.Handle("/api/v1/alerts", enforceMethods(r.noop, "GET"))
	mux.Handle("/api/v1/rules", enforceMethods(r.noop, "GET"))
	mux.Handle("/api/v2/silences", enforceMethods(r.silences, "GET", "POST"))
	mux.Handle("/api/v2/silences/", enforceMethods(r.silences, "GET", "POST"))
	mux.Handle("/api/v2/silence/", enforceMethods(r.deleteSilence, "DELETE"))
	r.mux = mux
	r.modifiers = map[string]func(*http.Response) error{
		"/api/v1/rules":  modifyAPIResponse(r.filterRules),
		"/api/v1/alerts": modifyAPIResponse(r.filterAlerts),
	}
	proxy.ModifyResponse = r.ModifyResponse
	return r
}

func (r *routes) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var lvalue string
	if r.labelLocation == "header" {
		lvalue = req.Header.Get(r.label)
	} else {
	  lvalue = req.URL.Query().Get(r.label)
	}
	if lvalue == "" {
		http.Error(w, fmt.Sprintf("Bad request. The %q query parameter must be provided.", r.label), http.StatusBadRequest)
		return
	}

	lvalues := strings.Split(lvalue, ",")

	req = req.WithContext(withLabelValue(req.Context(), lvalues))
	// Remove the proxy label from the query parameters.
	q := req.URL.Query()
	q.Del(r.label)
	req.URL.RawQuery = q.Encode()

	r.mux.ServeHTTP(w, req)
}

func (r *routes) ModifyResponse(resp *http.Response) error {
	m, found := r.modifiers[resp.Request.URL.Path]
	if !found {
		// Return the server's response unmodified.
		return nil
	}
	return m(resp)
}

func enforceMethods(h http.HandlerFunc, methods ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for _, m := range methods {
			if m == req.Method {
				h(w, req)
				return
			}
		}
		http.NotFound(w, req)
	})
}

type ctxKey int

const keyLabel ctxKey = iota

func mustLabelValue(ctx context.Context) []string {
	lvalues, ok := ctx.Value(keyLabel).([]string)
	if !ok {
		panic(fmt.Sprintf("can't find the %q value in the context", keyLabel))
	}
	if lvalues == nil || len(lvalues) == 0 {
		panic(fmt.Sprintf("empty %q value in the context", keyLabel))
	}
	return lvalues
}

func createLabelMatcher(ctx context.Context, label string) *labels.Matcher {
	lvalues := mustLabelValue(ctx)

	fmt.Println("label " + label + " should be: " + strings.Join(lvalues, ","))
	if len(lvalues) == 1 {
		return &labels.Matcher{
			Name:  label,
			Type:  labels.MatchEqual,
			Value: lvalues[0],
		}
	} else if len(lvalues) > 1 {
		return &labels.Matcher{
			Name:  label,
			Type:  labels.MatchRegexp,
			Value: "^(?:" + strings.Join(lvalues, "|") + ")$",
		}
	}
	panic(fmt.Sprintf("label values has invalid size %d", len(lvalues)))
}

func withLabelValue(ctx context.Context, lvalues []string) context.Context {
	return context.WithValue(ctx, keyLabel, lvalues)
}

func (r *routes) noop(w http.ResponseWriter, req *http.Request) {
	r.handler.ServeHTTP(w, req)
}

func (r *routes) query(w http.ResponseWriter, req *http.Request) {
	expr, err := parser.ParseExpr(req.FormValue("query"))
	if err != nil {
		return
	}

	e := NewEnforcer([]*labels.Matcher{
		createLabelMatcher(req.Context(), r.label),
	}...)
	if err := e.EnforceNode(expr); err != nil {
		return
	}

	q := req.URL.Query()
	q.Set("query", expr.String())
	req.URL.RawQuery = q.Encode()

	r.handler.ServeHTTP(w, req)
}

func (r *routes) series(w http.ResponseWriter, req *http.Request) {
	if req.Form == nil {
		req.ParseMultipartForm(32 << 20)
	}
	matches := req.Form["match[]"];
	q := req.URL.Query()
	q.Del("match[]")

  if matches != nil {
		for _, query := range matches {
			expr, err := parser.ParseExpr(query)
			if err != nil {
				return
			}

			e := NewEnforcer([]*labels.Matcher{
				createLabelMatcher(req.Context(), r.label),
			}...)
			if err := e.EnforceNode(expr); err != nil {
				return
			}

			q.Add("match[]", expr.String())
			fmt.Println("new query: " + expr.String())
		}
	}

	req.URL.RawQuery = q.Encode()

	r.handler.ServeHTTP(w, req)
}

func (r *routes) federate(w http.ResponseWriter, req *http.Request) {
	matcher := createLabelMatcher(req.Context(), r.label)

	q := req.URL.Query()
	q.Set("match[]", "{"+matcher.String()+"}")
	req.URL.RawQuery = q.Encode()

	r.handler.ServeHTTP(w, req)
}
