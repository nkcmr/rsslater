package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pkg/errors"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"

	"github.com/go-kit/kit/transport/http/jsonrpc"
)

func main() {
	_ = rootCommand().Execute()
}

func genericEndpointCode[Request, Response any](
	ep func(context.Context, Request) (Response, error),
	decoder func(context.Context, json.RawMessage) (Request, error),
	encoder func(context.Context, Response) (json.RawMessage, error),
) jsonrpc.EndpointCodec {
	return jsonrpc.EndpointCodec{
		Endpoint: func(ctx context.Context, request any) (any, error) {
			return ep(ctx, request.(Request))
		},
		Decode: func(ctx context.Context, rm json.RawMessage) (request interface{}, err error) {
			return decoder(ctx, rm)
		},
		Encode: func(ctx context.Context, i interface{}) (response json.RawMessage, err error) {
			return encoder(ctx, i.(Response))
		},
	}
}

//go:embed public
var publicFS embed.FS

func rootCommand() *cobra.Command {
	var args struct {
		listenAddr      string
		tlsCert, tlsKey string
		storageFilename string
		origin          string
		autoCert        bool
	}
	cmd := &cobra.Command{
		Use: "rsslater",
		Run: runWithError(func(c *cobra.Command, s []string) error {
			originURL, err := url.ParseRequestURI(args.origin)
			if err != nil {
				return errors.Wrap(err, "failed to parse origin flag")
			}
			originURL.Path = ""
			originURL.RawPath = ""
			originURL.RawQuery = ""
			originURL.RawFragment = ""
			originURL.User = nil

			web, err := webauthn.New(&webauthn.Config{
				RPDisplayName: "RSSLater",
				RPID:          originURL.Hostname(),
				RPOrigin:      originURL.String(),
			})
			if err != nil {
				return errors.Wrap(err, "failed to initialize webauthn")
			}
			str, err := newJSONStorage(args.storageFilename)
			if err != nil {
				return errors.Wrap(err, "failed to initialize json storage")
			}
			state, err := str.state(c.Context())
			if err != nil {
				return errors.Wrap(err, "failed to get storage state")
			}
			if state == waitForUserSetup {
				fmt.Printf("Navigate to the server in a browser to finish setup: %s\n", originURL)
			}
			svc := &service{
				origin:      originURL.String(),
				sessionData: map[string]any{},
				str:         str,
				web:         web,
			}
			if err := svc.str.init(c.Context()); err != nil {
				return errors.Wrap(err, "storage failed to initialized")
			}

			r := chi.NewRouter()
			r.Use(middleware.Logger)
			jrpc := jsonrpc.NewServer(jsonrpc.EndpointCodecMap{
				"server_initialized": genericEndpointCode(
					svc.isInitialized,
					func(ctx context.Context, _ json.RawMessage) (struct{}, error) {
						return struct{}{}, nil
					},
					func(ctx context.Context, result bool) (json.RawMessage, error) {
						return json.Marshal(result)
					},
				),
				"webauthn:registration:begin": genericEndpointCode(
					svc.webauthnRegBegin,
					func(ctx context.Context, paramsJson json.RawMessage) (webauthnRegBeginRequest, error) {
						var req webauthnRegBeginRequest
						if err := json.Unmarshal(paramsJson, &req); err != nil {
							return webauthnRegBeginRequest{}, errors.Wrap(err, "invalid json")
						}
						return req, nil
					},
					func(ctx context.Context, result webauthnRegBeginResponse) (json.RawMessage, error) {
						return json.Marshal(result)
					},
				),
				"webauthn:registration:finish": genericEndpointCode(
					svc.webauthnRegFinish,
					func(ctx context.Context, paramsJson json.RawMessage) (webauthnRegFinishRequest, error) {
						var req webauthnRegFinishRequest
						if err := json.Unmarshal(paramsJson, &req); err != nil {
							return webauthnRegFinishRequest{}, errors.Wrap(err, "invalid json")
						}
						return req, nil
					},
					func(ctx context.Context, result webauthnRegFinishResponse) (json.RawMessage, error) {
						return json.Marshal(result)
					},
				),
				"webauthn:login:begin": genericEndpointCode(
					svc.webauthnLoginBegin,
					func(ctx context.Context, _ json.RawMessage) (webauthnLoginBeginRequest, error) {
						return webauthnLoginBeginRequest{}, nil
					},
					func(ctx context.Context, result webauthnLoginBeginResponse) (json.RawMessage, error) {
						return json.Marshal(result)
					},
				),
				"webauthn:login:finish": genericEndpointCode(
					svc.webauthnLoginFinish,
					func(ctx context.Context, paramsJson json.RawMessage) (webauthnLoginFinishRequest, error) {
						var req webauthnLoginFinishRequest
						if err := json.Unmarshal(paramsJson, &req); err != nil {
							return webauthnLoginFinishRequest{}, errors.Wrap(err, "invalid json")
						}
						return req, nil
					},
					func(ctx context.Context, result webauthnLoginFinishResponse) (json.RawMessage, error) {
						return json.Marshal(result)
					},
				),
				"webauthn:list_keys": genericEndpointCode(
					svc.webauthnListKeys,
					func(ctx context.Context, paramsJson json.RawMessage) (webauthnListKeysRequest, error) {
						var req webauthnListKeysRequest
						if err := json.Unmarshal(paramsJson, &req); err != nil {
							return webauthnListKeysRequest{}, errors.Wrap(err, "invalid json")
						}
						return req, nil
					},
					func(ctx context.Context, result webauthnListKeysResponse) (json.RawMessage, error) {
						return json.Marshal(result)
					},
				),
				"gen_feed_url": genericEndpointCode(
					svc.genFeedURL,
					func(ctx context.Context, paramsJson json.RawMessage) (genFeedURLRequest, error) {
						var req genFeedURLRequest
						if err := json.Unmarshal(paramsJson, &req); err != nil {
							return genFeedURLRequest{}, errors.Wrap(err, "invalid json")
						}
						return req, nil
					},
					func(ctx context.Context, r string) (json.RawMessage, error) {
						return json.Marshal(r)
					},
				),
				"gen_bookmarklet": genericEndpointCode(
					svc.genSaveForLaterBookmark,
					func(ctx context.Context, paramsJson json.RawMessage) (genSaveForLaterBookmarkRequest, error) {
						var req genSaveForLaterBookmarkRequest
						if err := json.Unmarshal(paramsJson, &req); err != nil {
							return genSaveForLaterBookmarkRequest{}, errors.Wrap(err, "invalid json")
						}
						return req, nil
					},
					func(ctx context.Context, r string) (json.RawMessage, error) {
						return json.Marshal(r)
					},
				),
				"save_for_later": genericEndpointCode(
					svc.saveForLater,
					func(ctx context.Context, paramsJson json.RawMessage) (saveForLaterRequest, error) {
						var req saveForLaterRequest
						if err := json.Unmarshal(paramsJson, &req); err != nil {
							return saveForLaterRequest{}, errors.Wrap(err, "invalid json")
						}
						return req, nil
					},
					func(ctx context.Context, _ struct{}) (json.RawMessage, error) {
						return json.RawMessage("null"), nil
					},
				),
			}, jsonrpc.ServerErrorEncoder(func(ctx context.Context, err error, w http.ResponseWriter) {
				e := jsonrpc.Error{
					Code:    jsonrpc.InternalError,
					Message: err.Error(),
				}
				if sc, ok := errors.Cause(err).(jsonrpc.ErrorCoder); ok {
					e.Code = sc.ErrorCode()
				}
				jsonrpc.DefaultErrorEncoder(ctx, e, w)
			}))
			r.Handle("/rpc/2022-12-22", jrpc)

			r.Get("/feed.xml", func(w http.ResponseWriter, r *http.Request) {
				password := r.URL.Query().Get("authKey")
				if password == "" {
					http.Error(w, "invalid auth", http.StatusUnauthorized)
					return
				}
				feed, err := svc.getFeed(r.Context(), getFeedRequest{
					Password: password,
				})
				if err != nil {
					http.Error(w, fmt.Sprintf("error occured while retrieving feed: %s", err.Error()), http.StatusInternalServerError)
					return
				}
				rssContents, err := feed.ToRss()
				if err != nil {
					http.Error(w, fmt.Sprintf("failed to render feed: %s", err.Error()), http.StatusInternalServerError)
					return
				}
				_, _ = io.WriteString(w, rssContents)
			})
			sub, err := fs.Sub(publicFS, "public")
			if err != nil {
				return errors.Wrap(err, "failed to seek embedded public FS")
			}
			r.Handle("/*", http.FileServer(http.FS(sub)))

			if args.autoCert {
				if !urlIsNonIPOn443(originURL) {
					return errors.New("origin url must be some domain name on https port")
				}
				return http.Serve(
					autocert.NewListener(originURL.Hostname()),
					cors.AllowAll().Handler(r),
				)
			} else if args.tlsCert != "" && args.tlsKey != "" {
				return http.ListenAndServeTLS(
					args.listenAddr,
					args.tlsCert,
					args.tlsKey,
					cors.AllowAll().Handler(r),
				)
			}
			return http.ListenAndServe(args.listenAddr, cors.AllowAll().Handler(r))
		}),
	}
	cmd.Flags().StringVar(&args.listenAddr, "listen-addr", "127.0.0.1:8080", "the address the server should listen on")
	cmd.Flags().BoolVar(&args.autoCert, "auto-cert", false, "automatically obtain TLS certificates for your origin (requires origin to be reachable via the whole Internet)")
	cmd.Flags().StringVar(&args.tlsCert, "tls-cert", "", "a tls certificate to use for HTTPS")
	cmd.Flags().StringVar(&args.tlsKey, "tls-key", "", "a tls key to use for HTTPS")
	cmd.Flags().StringVar(&args.storageFilename, "storage-file", "./rsslater-storage.json", "where the storage file is written/read")
	cmd.Flags().StringVar(&args.origin, "origin", "", "the publicly reachable url of your server")
	return cmd
}

func urlIsNonIPOn443(u *url.URL) bool {
	hostname := u.Host
	if strings.ContainsAny(hostname, ":") {
		splitHost, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			panic(fmt.Sprintf("urlIsNonIPOn443: assumed origin url was well-formed, guess not: %s", err.Error()))
		}
		if port != "443" {
			return false
		}
		hostname = splitHost
	} else if u.Scheme != "https" {
		return false
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		// hostname is actually an IP address
		return false
	}
	return true
}

func runWithError(fn func(*cobra.Command, []string) error) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		if err := fn(cmd, args); err != nil {
			fatal(err.Error())
		}
	}
}

func fatal(message string) {
	fmt.Fprintf(os.Stderr, "%s: error: %s\n", filepath.Base(os.Args[0]), message)
	os.Exit(1)
}
