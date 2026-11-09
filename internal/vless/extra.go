package vless

import (
	"encoding/json"
	"errors"
	"sort"
)

// xhttp's "extra" is the rest of Xray's xhttpSettings (SplitHTTPConfig)
// as a share link or a subscription carries it, and its downloadSettings
// is a whole streamSettings. xray.exe runs with the administrator's
// rights, and some keys there act on the machine, not on the connection:
// tlsSettings.masterKeyLog is a file Xray appends TLS keys to,
// certificates are files it reads, sockopt sets marks and interfaces of
// its sockets. Only the keys below pass (CleanExtra): at import and again
// when the config is built, so settings saved before or restored from a
// backup pass the same way.

// xhttpExtraKeys: what of SplitHTTPConfig shapes the connection itself.
// Xray takes host, path and mode from the link, not from extra.
var xhttpExtraKeys = map[string]bool{
	"headers": true, "xPaddingBytes": true, "xPaddingObfsMode": true, "xPaddingKey": true,
	"xPaddingHeader": true, "xPaddingPlacement": true, "xPaddingMethod": true,
	"uplinkHTTPMethod": true, "sessionIDPlacement": true, "sessionIDKey": true,
	"sessionIDTable": true, "sessionIDLength": true, "seqPlacement": true, "seqKey": true,
	"uplinkDataPlacement": true, "uplinkDataKey": true, "uplinkChunkSize": true,
	"noGRPCHeader": true, "noSSEHeader": true, "scMaxEachPostBytes": true,
	"scMinPostsIntervalMs": true, "scMaxBufferedPosts": true, "scStreamUpServerSecs": true,
	"serverMaxHeaderBytes": true, "xmux": true, "downloadSettings": true,
}

// downloadKeys: the download half's address and its transport.
var downloadKeys = map[string]bool{
	"address": true, "port": true, "network": true, "security": true,
	"tlsSettings": true, "realitySettings": true, "xhttpSettings": true, "splithttpSettings": true,
}

// tlsClientKeys: a client's TLS settings that name and check the server.
// allowInsecure is not among them: HyRoute always checks the certificate.
var tlsClientKeys = map[string]bool{
	"serverName": true, "alpn": true, "fingerprint": true, "pinnedPeerCertSha256": true,
	"verifyPeerCertByName": true, "echConfigList": true, "minVersion": true, "maxVersion": true,
	"cipherSuites": true, "curvePreferences": true, "enableSessionResumption": true,
}

// realityClientKeys: a REALITY client's settings.
var realityClientKeys = map[string]bool{
	"serverName": true, "fingerprint": true, "publicKey": true, "password": true,
	"shortId": true, "spiderX": true, "mldsa65Verify": true,
}

// CleanExtra returns xhttp's extra with only the keys Xray may take from
// a link, and the paths of the keys it dropped ("downloadSettings.sockopt").
// An extra that is not a JSON object is an error; "" stays "".
func CleanExtra(extra string) (string, []string, error) {
	if extra == "" {
		return "", nil, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(extra), &m); err != nil || m == nil {
		return "", nil, errors.New("xhttp extra: нужен JSON-объект")
	}
	var dropped []string
	out := cleanObject(m, "", xhttpExtraKeys, &dropped, func(k string, v json.RawMessage, path string) (json.RawMessage, bool) {
		if k != "downloadSettings" {
			return v, true
		}
		return cleanDownload(v, path, &dropped)
	})
	if len(out) == 0 {
		return "", dropped, nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", nil, err
	}
	return string(b), dropped, nil
}

// cleanObject keeps the keys of m in allowed, each through sub (nil: as
// it is); sub returns false to drop a value it cannot read.
func cleanObject(m map[string]json.RawMessage, prefix string, allowed map[string]bool, dropped *[]string,
	sub func(k string, v json.RawMessage, path string) (json.RawMessage, bool)) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		path := prefix + k
		if !allowed[k] {
			*dropped = append(*dropped, path)
			continue
		}
		v := m[k]
		if sub != nil {
			var ok bool
			if v, ok = sub(k, v, path); !ok {
				*dropped = append(*dropped, path)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// cleanDownload is downloadSettings: a streamSettings of its own.
func cleanDownload(v json.RawMessage, path string, dropped *[]string) (json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(v, &m) != nil || m == nil {
		return nil, false
	}
	out := cleanObject(m, path+".", downloadKeys, dropped, func(k string, v json.RawMessage, path string) (json.RawMessage, bool) {
		switch k {
		case "tlsSettings":
			return cleanFlat(v, path, tlsClientKeys, dropped)
		case "realitySettings":
			return cleanFlat(v, path, realityClientKeys, dropped)
		case "xhttpSettings", "splithttpSettings":
			// The download half's own xhttp, without a download half of
			// its own or an extra Xray would read again.
			keys := map[string]bool{"host": true, "path": true, "mode": true}
			for key := range xhttpExtraKeys {
				keys[key] = key != "downloadSettings"
			}
			return cleanFlat(v, path, keys, dropped)
		}
		return v, true
	})
	b, err := json.Marshal(out)
	return b, err == nil
}

// cleanFlat keeps the allowed keys of an object, their values as they are.
func cleanFlat(v json.RawMessage, path string, allowed map[string]bool, dropped *[]string) (json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(v, &m) != nil || m == nil {
		return nil, false
	}
	b, err := json.Marshal(cleanObject(m, path+".", allowed, dropped, nil))
	return b, err == nil
}
