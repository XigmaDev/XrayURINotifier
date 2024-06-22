package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func jsonFileMaker(data map[string]interface{}, uid string) (string, error) {
	// Construct file path
	file := "configs/" + uid + ".json"

	// Create directory if it doesn't exist
	if _, err := os.Stat("configs"); os.IsNotExist(err) {
		err := os.Mkdir("configs", 0755)
		if err != nil {
			return "", err
		}
	}

	// Write JSON data to file
	outfile, err := os.Create(file)
	if err != nil {
		return "", err
	}
	defer outfile.Close()

	err = json.NewEncoder(outfile).Encode(data)
	if err != nil {
		return "", err
	}

	return file, nil
}

func splitter(uri, target string) string {
	var spx string

	if strings.Contains(uri, target) {
		if strings.Contains(uri, "&") {
			spx = strings.Split(uri, target)[1]
			spx = strings.Split(spx, "&")[0]
		} else if strings.Contains(uri, "#") {
			spx = strings.Split(uri, target)[1]
			spx = strings.Split(spx, "#")[0]
		}
	}

	return spx
}

func inboundGenerator(host string, port int, socksport int, tport int) ([]byte, error) {
	inbound := map[string]interface{}{
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag":      "transparent",
				"port":     tport,
				"protocol": "dokodemo-door",
				"settings": map[string]interface{}{
					"network":        "tcp,udp",
					"followRedirect": true,
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
				},
				"streamSettings": map[string]interface{}{
					"sockopt": map[string]interface{}{
						"tproxy": "tproxy",
						"mark":   255,
					},
				},
			},
			map[string]interface{}{
				"tag":      "socks",
				"port":     socksport,
				"listen":   host,
				"protocol": "socks",
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
					"routeOnly":    false,
				},
				"settings": map[string]interface{}{
					"auth":             "noauth",
					"udp":              true,
					"allowTransparent": false,
				},
			},
			map[string]interface{}{
				"tag":      "http",
				"port":     port,
				"listen":   host,
				"protocol": "http",
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
					"routeOnly":    false,
				},
				"settings": map[string]interface{}{
					"auth":             "noauth",
					"udp":              true,
					"allowTransparent": false,
				},
			},
		},
	}

	// Convert to JSON
	inboundJSON, err := json.Marshal(inbound)
	if err != nil {
		fmt.Println("Error marshalling inbound config:", err)
		return nil, err
	}

	return inboundJSON, err
}

func getDestinationPort(uri, address string) int {
	portParts := strings.Split(uri, address+":")
	if len(portParts) > 1 {
		port := strings.Split(portParts[1], "?")[0]
		destPort, _ := strconv.Atoi(port)
		return destPort
	}
	return 0
}

func convertURIRealityJSON(host string, port int, socksport int, tport int, uri string) (string, error) {
	// Parse URI components
	protocol := strings.Split(uri, "://")[0]
	uid := strings.Split(uri, "//")[1]
	uid = strings.Split(uid, "@")[0]
	address := strings.Split(uri, "@")[1]
	address = strings.Split(address, ":")[0]
	destinationPortStr := strings.Split(strings.Split(uri, address+":")[1], "?")[0]
	destinationPort := 0
	if len(destinationPortStr) > 0 {
		var err error
		destinationPort, err = strconv.Atoi(destinationPortStr)
		if err != nil {
			return "", err
		}
	}
	network := splitter(uri, "type=")
	security := splitter(uri, "security=")
	sni := splitter(uri, "sni=")
	fp := splitter(uri, "fp=")
	pbk := splitter(uri, "pbk=")
	sid := splitter(uri, "sid=")
	spx := splitter(uri, "spx=")
	flow := splitter(uri, "flow=")

	// Construct data JSON
	data := map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "",
			"error":    "",
			"loglevel": "warning",
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag":      "proxy",
				"protocol": protocol,
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": address,
							"port":    destinationPort,
							"users": []interface{}{
								map[string]interface{}{
									"id":         uid,
									"alterId":    0,
									"email":      "t@t.tt",
									"security":   "auto",
									"encryption": "none",
									"flow":       flow,
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network":  network,
					"security": security,
					"realitySettings": map[string]interface{}{
						"serverName":  sni,
						"fingerprint": fp,
						"show":        false,
						"publicKey":   pbk,
						"shortId":     sid,
						"spiderX":     spx,
					},
				},
				"mux": map[string]interface{}{
					"enabled":     false,
					"concurrency": -1,
				},
			},
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			},
			map[string]interface{}{
				"tag":      "block",
				"protocol": "blackhole",
				"settings": map[string]interface{}{
					"response": map[string]interface{}{
						"type": "http",
					},
				},
			},
		},
	}

	// Handle headers if host= exists in URI
	if hostHeader := splitter(uri, "host="); hostHeader != "" {
		headerType := "http"
		if headerTypeValue := splitter(uri, "headertype="); headerTypeValue != "" {
			headerType = headerTypeValue
		}

		path := []string{"/"}
		if pathValue := splitter(uri, "path="); pathValue != "" {
			path = []string{pathValue}
		}

		headers := map[string]interface{}{
			"tcpSettings": map[string]interface{}{
				"header": map[string]interface{}{
					"type": headerType,
					"request": map[string]interface{}{
						"version": "1.1",
						"method":  "GET",
						"path":    path,
						"headers": map[string]interface{}{
							"Host":            []string{hostHeader},
							"User-Agent":      []string{""},
							"Accept-Encoding": []string{"gzip, deflate"},
							"Connection":      []string{"keep-alive"},
							"Pragma":          "no-cache",
						},
					},
				},
			},
		}

		// Update streamSettings with headers
		streamSettings, ok := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
		if ok {
			streamSettings["tcpSettings"] = headers["tcpSettings"]
		}
	}

	// Handle grpcSettings if network is grpc
	if network == "grpc" {
		serviceName := splitter(uri, "serviceName=")
		grpcSettings := map[string]interface{}{
			"grpcSettings": map[string]interface{}{
				"serviceName":           serviceName,
				"multiMode":             false,
				"idle_timeout":          60,
				"health_check_timeout":  20,
				"permit_without_stream": false,
				"initial_windows_size":  0,
			},
		}

		// Update streamSettings with grpcSettings
		streamSettings, ok := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
		if ok {
			streamSettings["grpcSettings"] = grpcSettings["grpcSettings"]
		}
	}

	// Merge with inbound configuration
	inboundConfig, err := inboundGenerator(host, port, socksport, tport)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(inboundConfig, &data)
	if err != nil {
		return "", err
	}

	// Generate and return JSON file path
	return jsonFileMaker(data, uid)
}

func convertURIVlessWSJSON(host string, port int, socksport int, tport int, uri string) (string, error) {
	// Parse URI components
	protocol := strings.Split(uri, "://")[0]
	uid := strings.Split(uri, "//")[1]
	uid = strings.Split(uid, "@")[0]
	address := strings.Split(uri, "@")[1]
	address = strings.Split(address, ":")[0]
	destinationPortStr := strings.Split(strings.Split(uri, address+":")[1], "?")[0]
	destinationPort := 0
	if len(destinationPortStr) > 0 {
		var err error
		destinationPort, err = strconv.Atoi(destinationPortStr)
		if err != nil {
			return "", err
		}
	}
	network := splitter(uri, "type=")

	headers := map[string]string{}
	if hostHeader := splitter(uri, "host="); hostHeader != "" {
		headers["Host"] = hostHeader
	}

	var path string
	if pathValue := splitter(uri, "path="); pathValue != "" {
		path = pathValue
	}

	data := map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "",
			"error":    "",
			"loglevel": "warning",
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag":      "proxy",
				"protocol": protocol,
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": address,
							"port":    destinationPort,
							"users": []interface{}{
								map[string]interface{}{
									"id":         uid,
									"alterId":    0,
									"email":      "t@t.tt",
									"security":   "auto",
									"encryption": "none",
									"flow":       "",
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": network,
					"wsSettings": map[string]interface{}{
						"path":    path,
						"headers": headers,
					},
				},
				"mux": map[string]interface{}{
					"enabled":     false,
					"concurrency": -1,
				},
			},
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			},
			map[string]interface{}{
				"tag":      "block",
				"protocol": "blackhole",
				"settings": map[string]interface{}{
					"response": map[string]interface{}{
						"type": "http",
					},
				},
			},
		},
	}

	// Handle security settings if present in URI
	if security := splitter(uri, "security="); security != "" {
		if security != "none" {
			sni := splitter(uri, "sni=")
			var alpn []string
			alpn_c := splitter(uri, "alpn=")
			if strings.Contains(alpn_c, "http/1.1") {
				alpn = append(alpn, "http/1.1")
			}
			if strings.Contains(alpn_c, "h2") {
				alpn = append(alpn, "h2")
			}
			if strings.Contains(alpn_c, "h3") {
				alpn = append(alpn, "h3")
			}

			tlsSettings := map[string]interface{}{
				"allowInsecure": true,
				"serverName":    sni,
				"alpn":          alpn,
				"show":          false,
			}

			// Update streamSettings with TLS settings
			streamSettings, ok := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
			if ok {
				streamSettings["security"] = security
				streamSettings["tlsSettings"] = tlsSettings
			}
		}
	}

	// Merge with inbound configuration
	inboundConfig, err := inboundGenerator(host, port, socksport, tport)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(inboundConfig, &data)
	if err != nil {
		return "", err
	}

	// Generate and return JSON file path
	return jsonFileMaker(data, uid)
}

func convertURIVlessTCPJSON(host string, port int, socksport int, tport int, uri string) (string, error) {
	// Parse URI components
	protocol := strings.Split(uri, "://")[0]
	uid := strings.Split(uri, "//")[1]
	uid = strings.Split(uid, "@")[0]
	address := strings.Split(uri, "@")[1]
	address = strings.Split(address, ":")[0]
	destinationPortStr := strings.Split(strings.Split(uri, address+":")[1], "?")[0]
	destinationPort := 0
	if len(destinationPortStr) > 0 {
		var err error
		destinationPort, err = strconv.Atoi(destinationPortStr)
		if err != nil {
			return "", err
		}
	}
	network := splitter(uri, "type=")

	data := map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "",
			"error":    "",
			"loglevel": "warning",
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag":      "proxy",
				"protocol": protocol,
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": address,
							"port":    destinationPort,
							"users": []interface{}{
								map[string]interface{}{
									"id":         uid,
									"alterId":    0,
									"email":      "t@t.tt",
									"security":   "auto",
									"encryption": "none",
									"flow":       "",
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": network,
				},
				"mux": map[string]interface{}{
					"enabled":     false,
					"concurrency": -1,
				},
			},
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			},
			map[string]interface{}{
				"tag":      "block",
				"protocol": "blackhole",
				"settings": map[string]interface{}{
					"response": map[string]interface{}{
						"type": "http",
					},
				},
			},
		},
	}

	// Handle headers if present in URI
	if hostHeader := splitter(uri, "host="); hostHeader != "" {
		headertype := "http"
		if headertypeValue := splitter(uri, "headertype="); headertypeValue != "" {
			headertype = headertypeValue
		}
		path := "/"
		if pathValue := splitter(uri, "path="); pathValue != "" {
			path = pathValue
		}

		headers := map[string]interface{}{
			"tcpSettings": map[string]interface{}{
				"header": map[string]interface{}{
					"type": headertype,
					"request": map[string]interface{}{
						"version": "1.1",
						"method":  "GET",
						"path":    path,
						"headers": map[string]interface{}{
							"Host":            []string{hostHeader},
							"User-Agent":      []string{""},
							"Accept-Encoding": []string{"gzip, deflate"},
							"Connection":      []string{"keep-alive"},
							"Pragma":          "no-cache",
						},
					},
				},
			},
		}

		// Update streamSettings with headers
		streamSettings, ok := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
		if ok {
			streamSettings["headers"] = headers
		}
	}

	// Handle security settings if present in URI
	if security := splitter(uri, "security="); security != "" {
		if security != "none" {
			sni := ""
			if sniValue := splitter(uri, "sni="); sniValue != "" {
				sni = sniValue
			}
			var alpn []string
			if alpnValue := splitter(uri, "alpn="); alpnValue != "" {
				if strings.Contains(alpnValue, "http/1.1") {
					alpn = append(alpn, "http/1.1")
				}
				if strings.Contains(alpnValue, "h2") {
					alpn = append(alpn, "h2")
				}
				if strings.Contains(alpnValue, "h3") {
					alpn = append(alpn, "h3")
				}
			}

			tlsSettings := map[string]interface{}{
				"allowInsecure": true,
				"serverName":    sni,
				"alpn":          alpn,
				"show":          false,
			}

			if fp := splitter(uri, "fp="); fp != "" {
				if fp != "none" {
					tlsSettings["fingerprint"] = fp
				}
			}

			// Update streamSettings with TLS settings
			streamSettings, ok := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
			if ok {
				streamSettings["security"] = security
				streamSettings["tlsSettings"] = tlsSettings
			}
		}
	}

	// Handle grpc settings if network is grpc
	if network == "grpc" {
		serviceName := ""
		if serviceNameValue := splitter(uri, "serviceName="); serviceNameValue != "" {
			serviceName = serviceNameValue
		}
		grpcSettings := map[string]interface{}{
			"serviceName":           serviceName,
			"multiMode":             false,
			"idle_timeout":          60,
			"health_check_timeout":  20,
			"permit_without_stream": false,
			"initial_windows_size":  0,
		}

		// Update streamSettings with grpc settings
		streamSettings, ok := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
		if ok {
			streamSettings["grpcSettings"] = grpcSettings
		}
	}

	// Merge with inbound configuration
	inboundConfig, err := inboundGenerator(host, port, socksport, tport)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(inboundConfig, &data)
	if err != nil {
		return "", err
	}

	// Generate and return JSON file path
	return jsonFileMaker(data, uid)
}

func convertURIVmessWSJSON(host string, port int, socksport int, tport int, uri string) (string, error) {
	// Decode base64 encoded URI segment
	uriParts := strings.Split(uri, "://")
	if len(uriParts) < 2 {
		return "", fmt.Errorf("invalid URI format")
	}
	decoded, err := base64.StdEncoding.DecodeString(uriParts[1])
	if err != nil {
		return "", fmt.Errorf("error decoding URI: %v", err)
	}

	// Parse decoded JSON
	var decodedJSON map[string]interface{}
	err = json.Unmarshal(decoded, &decodedJSON)
	if err != nil {
		return "", fmt.Errorf("error decoding JSON: %v", err)
	}

	protocol := strings.Split(uri, "://")[0]
	uid := decodedJSON["id"].(string)
	address := decodedJSON["add"].(string)
	destinationPort := int(decodedJSON["port"].(float64))
	network := decodedJSON["net"].(string)

	headers := make(map[string]string)
	if hostValue, ok := decodedJSON["host"].(string); ok {
		headers["Host"] = hostValue
	}

	path := "/"
	if pathValue, ok := decodedJSON["path"].(string); ok {
		path = pathValue
	}

	data := map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "",
			"error":    "",
			"loglevel": "warning",
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag":      "proxy",
				"protocol": protocol,
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": address,
							"port":    destinationPort,
							"users": []interface{}{
								map[string]interface{}{
									"id":         uid,
									"alterId":    0,
									"email":      "t@t.tt",
									"security":   "auto",
									"encryption": "none",
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": network,
					"wsSettings": map[string]interface{}{
						"path":    path,
						"headers": headers,
					},
				},
				"mux": map[string]interface{}{
					"enabled":     false,
					"concurrency": -1,
				},
			},
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			},
			map[string]interface{}{
				"tag":      "block",
				"protocol": "blackhole",
				"settings": map[string]interface{}{
					"response": map[string]interface{}{
						"type": "http",
					},
				},
			},
		},
	}

	if tlsValue, ok := decodedJSON["tls"].(string); ok && tlsValue != "none" {
		security := tlsValue
		sni := ""
		if sniValue, ok := decodedJSON["sni"].(string); ok {
			sni = sniValue
		}
		var alpn []string
		if alpnValue, ok := decodedJSON["alpn"].(string); ok {
			if strings.Contains(alpnValue, "http/1.1") {
				alpn = append(alpn, "http/1.1")
			}
			if strings.Contains(alpnValue, "h2") {
				alpn = append(alpn, "h2")
			}
			if strings.Contains(alpnValue, "h3") {
				alpn = append(alpn, "h3")
			}
		}

		tlsSettings := map[string]interface{}{
			"allowInsecure": true,
			"serverName":    sni,
			"alpn":          alpn,
			"show":          false,
		}

		if fpValue, ok := decodedJSON["fp"].(string); ok && fpValue != "none" {
			tlsSettings["fingerprint"] = fpValue
		}

		// Update streamSettings with TLS settings
		streamSettings, ok := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
		if ok {
			streamSettings["security"] = security
			streamSettings["tlsSettings"] = tlsSettings
		}
	}

	// Merge with inbound configuration
	inboundConfig, err := inboundGenerator(host, port, socksport, tport)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(inboundConfig, &data)
	if err != nil {
		return "", err
	}

	// Generate and return JSON file path
	return jsonFileMaker(data, uid)
}

func convertURIVmessTCPJSON(host string, port int, socksport int, tport int, uri string) (string, error) {
	// Decode base64 encoded URI segment
	uriParts := strings.Split(uri, "://")
	if len(uriParts) < 2 {
		return "", fmt.Errorf("invalid URI format")
	}
	decoded, err := base64.StdEncoding.DecodeString(uriParts[1])
	if err != nil {
		return "", fmt.Errorf("error decoding URI: %v", err)
	}

	// Parse decoded JSON
	var decodedJSON map[string]interface{}
	err = json.Unmarshal(decoded, &decodedJSON)
	if err != nil {
		return "", fmt.Errorf("error decoding JSON: %v", err)
	}

	protocol := strings.Split(uri, "://")[0]
	uid := decodedJSON["id"].(string)
	address := decodedJSON["add"].(string)
	destinationPort := int(decodedJSON["port"].(float64))
	network := decodedJSON["net"].(string)

	data := map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "",
			"error":    "",
			"loglevel": "warning",
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag":      "proxy",
				"protocol": protocol,
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": address,
							"port":    destinationPort,
							"users": []interface{}{
								map[string]interface{}{
									"id":         uid,
									"alterId":    0,
									"email":      "t@t.tt",
									"security":   "auto",
									"encryption": "none",
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": network,
				},
				"mux": map[string]interface{}{
					"enabled":     false,
					"concurrency": -1,
				},
			},
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			},
			map[string]interface{}{
				"tag":      "block",
				"protocol": "blackhole",
				"settings": map[string]interface{}{
					"response": map[string]interface{}{
						"type": "http",
					},
				},
			},
		},
	}

	headers := map[string]interface{}{}
	if hostValue, ok := decodedJSON["host"].(string); ok && hostValue != "" {
		hostHTTP := hostValue
		headertype := "http"
		if typeValue, ok := decodedJSON["type"].(string); ok {
			headertype = typeValue
		}
		path := []string{"/"}
		if pathValue, ok := decodedJSON["path"].(string); ok {
			path = []string{pathValue}
		}

		headers = map[string]interface{}{
			"tcpSettings": map[string]interface{}{
				"header": map[string]interface{}{
					"type": headertype,
					"request": map[string]interface{}{
						"version": "1.1",
						"method":  "GET",
						"path":    path,
						"headers": map[string][]string{
							"Host":            {hostHTTP},
							"User-Agent":      {""},
							"Accept-Encoding": {"gzip, deflate"},
							"Connection":      {"keep-alive"},
							"Pragma":          {"no-cache"},
						},
					},
				},
			},
		}
		data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})["headers"] = headers
	}

	if tlsValue, ok := decodedJSON["tls"].(string); ok && tlsValue != "" && tlsValue != "none" {
		security := tlsValue
		sni := ""
		if sniValue, ok := decodedJSON["sni"].(string); ok {
			sni = sniValue
		}
		alpn := []string{}
		if alpnValue, ok := decodedJSON["alpn"].(string); ok {
			if strings.Contains(alpnValue, "http/1.1") {
				alpn = append(alpn, "http/1.1")
			}
			if strings.Contains(alpnValue, "h2") {
				alpn = append(alpn, "h2")
			}
			if strings.Contains(alpnValue, "h3") {
				alpn = append(alpn, "h3")
			}
		}

		tlsSettings := map[string]interface{}{
			"security": security,
			"tlsSettings": map[string]interface{}{
				"allowInsecure": true,
				"serverName":    sni,
				"alpn":          alpn,
				"show":          false,
			},
		}

		if fpValue, ok := decodedJSON["fp"].(string); ok && fpValue != "" && fpValue != "none" {
			tlsSettings["tlsSettings"].(map[string]interface{})["fingerprint"] = fpValue
		}

		// Update streamSettings with TLS settings
		streamSettings := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
		for k, v := range tlsSettings {
			streamSettings[k] = v
		}
	}

	if network == "grpc" {
		serviceName := ""
		if pathValue, ok := decodedJSON["path"].(string); ok {
			serviceName = pathValue
		}
		grpcSettings := map[string]interface{}{
			"grpcSettings": map[string]interface{}{
				"serviceName":           serviceName,
				"multiMode":             false,
				"idle_timeout":          60,
				"health_check_timeout":  20,
				"permit_without_stream": false,
				"initial_windows_size":  0,
			},
		}

		streamSettings := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
		for k, v := range grpcSettings {
			streamSettings[k] = v
		}
	}

	// Merge with inbound configuration
	inboundConfig, err := inboundGenerator(host, port, socksport, tport)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(inboundConfig, &data)
	if err != nil {
		return "", err
	}

	// Generate and return JSON file path
	return jsonFileMaker(data, uid)
}

func convertURITrojanRealityJSON(host string, port int, socksport int, tport int, uri string) (string, error) {
	// Split URI to extract components
	uriParts := strings.Split(uri, "://")
	if len(uriParts) < 2 {
		return "", fmt.Errorf("invalid URI format")
	}
	protocol := uriParts[0]
	password := strings.Split(uriParts[1], "@")[0]
	address := strings.Split(strings.Split(uriParts[1], "@")[1], ":")[0]
	destinationPort := getDestinationPort(uri, address)
	network := splitter(uri, "type=")

	// Extract security settings
	security := splitter(uri, "security=")
	sni := splitter(uri, "sni=")
	fp := splitter(uri, "fp=")
	pbk := splitter(uri, "pbk=")

	// Optional parameters
	sid := splitter(uri, "sid=")
	spx := splitter(uri, "spx=")
	flow := splitter(uri, "flow=")

	// Initialize data structure
	data := map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "",
			"error":    "",
			"loglevel": "warning",
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag":      "proxy",
				"protocol": protocol,
				"settings": map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{
							"address":  address,
							"method":   "chacha20",
							"ota":      false,
							"password": password,
							"port":     destinationPort,
							"level":    1,
							"flow":     flow,
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": network,
					"security": map[string]interface{}{
						"security": security,
						"realitySettings": map[string]interface{}{
							"serverName":  sni,
							"fingerprint": fp,
							"show":        false,
							"publicKey":   pbk,
							"shortId":     sid,
							"spiderX":     spx,
						},
					},
				},
				"mux": map[string]interface{}{
					"enabled":     false,
					"concurrency": -1,
				},
			},
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			},
			map[string]interface{}{
				"tag":      "block",
				"protocol": "blackhole",
				"settings": map[string]interface{}{
					"response": map[string]interface{}{
						"type": "http",
					},
				},
			},
		},
	}

	// Handle optional HTTP headers
	if hostValue := splitter(uri, "host="); hostValue != "" {
		headertype := "http"
		if headertypeValue := splitter(uri, "headertype="); headertypeValue != "" {
			headertype = headertypeValue
		}
		path := []string{"/"}
		if pathValue := splitter(uri, "path="); pathValue != "" {
			path = []string{pathValue}
		}

		headers := map[string]interface{}{
			"tcpSettings": map[string]interface{}{
				"header": map[string]interface{}{
					"type": headertype,
					"request": map[string]interface{}{
						"version": "1.1",
						"method":  "GET",
						"path":    path,
						"headers": map[string][]string{
							"Host":            {hostValue},
							"User-Agent":      {""},
							"Accept-Encoding": {"gzip, deflate"},
							"Connection":      {"keep-alive"},
							"Pragma":          {"no-cache"},
						},
					},
				},
			},
		}
		data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})["headers"] = headers
	}

	// Handle gRPC settings
	if network == "grpc" {
		serviceName := ""
		if serviceNameValue := splitter(uri, "serviceName="); serviceNameValue != "" {
			serviceName = serviceNameValue
		}
		grpcSettings := map[string]interface{}{
			"grpcSettings": map[string]interface{}{
				"serviceName":           serviceName,
				"multiMode":             false,
				"idle_timeout":          60,
				"health_check_timeout":  20,
				"permit_without_stream": false,
				"initial_windows_size":  0,
			},
		}

		streamSettings := data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
		for k, v := range grpcSettings {
			streamSettings[k] = v
		}
	}

	// Merge with inbound configuration
	inboundConfig, err := inboundGenerator(host, port, socksport, tport)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(inboundConfig, &data)
	if err != nil {
		return "", err
	}

	// Generate and return JSON file path
	return jsonFileMaker(data, password)
}

func convertURITrojanWSJSON(host string, port int, socksport int, tport int, uri string) (string, error) {
	// Split URI to extract components
	uriParts := strings.Split(uri, "://")
	if len(uriParts) < 2 {
		return "", fmt.Errorf("invalid URI format")
	}
	protocol := uriParts[0]
	password := strings.Split(uriParts[1], "@")[0]
	address := strings.Split(strings.Split(uriParts[1], "@")[1], ":")[0]
	destinationPort := getDestinationPort(uri, address)
	network := splitter(uri, "type=")
	headers := make(map[string]string)

	// Extract optional HTTP headers
	if hostValue := splitter(uri, "host="); hostValue != "" {
		headers["Host"] = hostValue
	}

	// Extract optional path
	path := "/"
	if pathValue := splitter(uri, "path="); pathValue != "" {
		path = pathValue
	}

	// Initialize data structure
	data := map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "",
			"error":    "",
			"loglevel": "warning",
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag":      "proxy",
				"protocol": protocol,
				"settings": map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{
							"address":  address,
							"method":   "chacha20",
							"ota":      false,
							"password": password,
							"port":     destinationPort,
							"level":    1,
							"flow":     "",
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": network,
					"wsSettings": map[string]interface{}{
						"path":    path,
						"headers": headers,
					},
				},
				"mux": map[string]interface{}{
					"enabled":     false,
					"concurrency": -1,
				},
			},
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			},
			map[string]interface{}{
				"tag":      "block",
				"protocol": "blackhole",
				"settings": map[string]interface{}{
					"response": map[string]interface{}{
						"type": "http",
					},
				},
			},
		},
	}

	// Handle optional TLS settings
	if security := splitter(uri, "security="); security != "none" {
		sni := splitter(uri, "sni=")
		alpn := []string{}
		if alpnValue := splitter(uri, "alpn="); alpnValue != "" {
			alpn_c := strings.Split(alpnValue, ",")
			for _, v := range alpn_c {
				if v == "http/1.1" || v == "h2" || v == "h3" {
					alpn = append(alpn, v)
				}
			}
		}

		newDict := map[string]interface{}{
			"security": security,
			"tlsSettings": map[string]interface{}{
				"allowInsecure": true,
				"serverName":    sni,
				"alpn":          alpn,
				"show":          false,
			},
		}
		for k, v := range newDict {
			data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})[k] = v
		}
	}

	// Merge with inbound configuration
	inboundConfig, err := inboundGenerator(host, port, socksport, tport)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(inboundConfig, &data)
	if err != nil {
		return "", err
	}

	// Generate and return JSON file path
	return jsonFileMaker(data, password)
}

func convertURITrojanTCPJSON(host string, port int, socksport int, tport int, uri string) (string, error) {
	// Split URI to extract components
	uriParts := strings.Split(uri, "://")
	if len(uriParts) < 2 {
		return "", fmt.Errorf("invalid URI format")
	}
	protocol := uriParts[0]
	password := strings.Split(uriParts[1], "@")[0]
	address := strings.Split(strings.Split(uriParts[1], "@")[1], ":")[0]
	destinationPort := getDestinationPort(uri, address)
	network := splitter(uri, "type=")

	// Initialize data structure
	data := map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "",
			"error":    "",
			"loglevel": "warning",
		},
		"outbounds": []interface{}{
			map[string]interface{}{
				"tag":      "proxy",
				"protocol": protocol,
				"settings": map[string]interface{}{
					"servers": []interface{}{
						map[string]interface{}{
							"address":  address,
							"method":   "chacha20",
							"ota":      false,
							"password": password,
							"port":     destinationPort,
							"level":    1,
							"flow":     "",
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": network,
				},
				"mux": map[string]interface{}{
					"enabled":     false,
					"concurrency": -1,
				},
			},
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			},
			map[string]interface{}{
				"tag":      "block",
				"protocol": "blackhole",
				"settings": map[string]interface{}{
					"response": map[string]interface{}{
						"type": "http",
					},
				},
			},
		},
	}

	// Handle optional HTTP headers
	if hostValue := splitter(uri, "host="); hostValue != "" {
		headertype := "http"
		if headertypeValue := splitter(uri, "headertype="); headertypeValue != "" {
			headertype = headertypeValue
		}

		path := "/"
		if pathValue := splitter(uri, "path="); pathValue != "" {
			path = pathValue
		}

		headers := map[string]interface{}{
			"tcpSettings": map[string]interface{}{
				"header": map[string]interface{}{
					"type": headertype,
					"request": map[string]interface{}{
						"version": "1.1",
						"method":  "GET",
						"path":    []string{path},
						"headers": map[string][]string{
							"Host":            {hostValue},
							"User-Agent":      {""},
							"Accept-Encoding": {"gzip, deflate"},
							"Connection":      {"keep-alive"},
							"Pragma":          {"no-cache"},
						},
					},
				},
			},
		}
		data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"] = headers
	}

	// Handle optional TLS settings
	if security := splitter(uri, "security="); security != "none" {
		sni := splitter(uri, "sni=")
		alpn := []string{}
		if alpnValue := splitter(uri, "alpn="); alpnValue != "" {
			alpn_c := strings.Split(alpnValue, ",")
			for _, v := range alpn_c {
				if v == "http/1.1" || v == "h2" || v == "h3" {
					alpn = append(alpn, v)
				}
			}
		}

		newDict := map[string]interface{}{
			"security": security,
			"tlsSettings": map[string]interface{}{
				"allowInsecure": true,
				"serverName":    sni,
				"alpn":          alpn,
				"show":          false,
			},
		}
		if fp := splitter(uri, "fp="); fp != "" && fp != "none" {
			newDict["tlsSettings"].(map[string]interface{})["fingerprint"] = fp
		}
		for k, v := range newDict {
			data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})[k] = v
		}
	}

	// Handle gRPC settings if network is "grpc"
	if network == "grpc" {
		serviceName := splitter(uri, "serviceName=")
		newDict := map[string]interface{}{
			"grpcSettings": map[string]interface{}{
				"serviceName":           serviceName,
				"multiMode":             false,
				"idle_timeout":          60,
				"health_check_timeout":  20,
				"permit_without_stream": false,
				"initial_windows_size":  0,
			},
		}
		for k, v := range newDict {
			data["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})[k] = v
		}
	}

	// Merge with inbound configuration
	inboundConfig, err := inboundGenerator(host, port, socksport, tport)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(inboundConfig, &data)
	if err != nil {
		return "", err
	}

	// Generate and return JSON file path
	return jsonFileMaker(data, password)
}

func vlessRealityChecker(uri string) bool {
	if strings.Contains(uri, "security=") && strings.Contains(uri, "vless://") {
		sec := strings.Split(uri, "security=")[1]
		if strings.Contains(sec, "&") {
			sec = sec[:strings.Index(sec, "&")]
		}
		if sec == "reality" {
			return true
		}
	}
	return false
}

func vlessWSChecker(uri string) bool {
	if strings.Contains(uri, "type=ws") && strings.Contains(uri, "vless://") {
		return true
	}
	return false
}

func vlessTCPChecker(uri string) bool {
	if (strings.Contains(uri, "type=tcp") || strings.Contains(uri, "type=grpc")) && strings.Contains(uri, "vless://") {
		return true
	}
	return false
}

func vmessWSChecker(uri string) bool {
	if strings.Contains(uri, "vmess://") {
		decoded, err := base64.RawURLEncoding.DecodeString(strings.Split(uri, "://")[1])
		if err != nil {
			return false
		}
		var data map[string]interface{}
		err = json.Unmarshal(decoded, &data)
		if err != nil {
			return false
		}
		if net, ok := data["net"].(string); ok && net == "ws" {
			return true
		}
	}
	return false
}

func vmessTCPChecker(uri string) bool {
	if strings.Contains(uri, "vmess://") {
		decoded, err := base64.RawURLEncoding.DecodeString(strings.Split(uri, "://")[1])
		if err != nil {
			return false
		}
		var data map[string]interface{}
		err = json.Unmarshal(decoded, &data)
		if err != nil {
			return false
		}
		net, ok := data["net"].(string)
		if ok && (net == "tcp" || net == "grpc") {
			return true
		}
	}
	return false
}

func trojanRealityChecker(uri string) bool {
	if strings.Contains(uri, "security=") && strings.Contains(uri, "trojan://") {
		sec := strings.Split(uri, "security=")[1]
		if strings.Contains(sec, "&") {
			sec = sec[:strings.Index(sec, "&")]
		}
		if sec == "reality" {
			return true
		}
	}
	return false
}

func trojanWSChecker(uri string) bool {
	if strings.Contains(uri, "type=ws") && strings.Contains(uri, "trojan://") {
		return true
	}
	return false
}

func trojanTCPChecker(uri string) bool {
	if (strings.Contains(uri, "type=tcp") || strings.Contains(uri, "type=grpc")) && strings.Contains(uri, "trojan://") {
		return true
	}
	return false
}

func convertURIToJSON(host string, port int, socksport int, tport int, uri string) string {
	file := "configs.json"
	if uri == "" {
		return ""
	}
	uri = strings.Replace(uri, "%2F", "/", -1)

	if vlessRealityChecker(uri) {
		file, _ = convertURIRealityJSON(host, port, socksport, tport, uri)
	} else if vlessWSChecker(uri) {
		file, _ = convertURIVlessWSJSON(host, port, socksport, tport, uri)
	} else if vlessTCPChecker(uri) {
		file, _ = convertURIVlessTCPJSON(host, port, socksport, tport, uri)
	} else if vmessWSChecker(uri) {
		file, _ = convertURIVmessWSJSON(host, port, socksport, tport, uri)
	} else if vmessTCPChecker(uri) {
		file, _ = convertURIVmessTCPJSON(host, port, socksport, tport, uri)
	} else if trojanRealityChecker(uri) {
		file, _ = convertURITrojanRealityJSON(host, port, socksport, tport, uri)
	} else if trojanWSChecker(uri) {
		file, _ = convertURITrojanWSJSON(host, port, socksport, tport, uri)
	} else if trojanTCPChecker(uri) {
		file, _ = convertURITrojanTCPJSON(host, port, socksport, tport, uri)
	}
	return file
}
