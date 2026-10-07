package wyze

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AlexxIT/go2rtc/internal/api"
	"github.com/AlexxIT/go2rtc/internal/app"
	"github.com/AlexxIT/go2rtc/internal/streams"
	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/gwell"
	"github.com/AlexxIT/go2rtc/pkg/wyze"
	"github.com/rs/zerolog"
)

type AccountConfig struct {
	APIKey   string `yaml:"api_key"`
	APIID    string `yaml:"api_id"`
	Password string `yaml:"password"`
}

var accounts map[string]AccountConfig

var log zerolog.Logger

func Init() {
	var v struct {
		Cfg map[string]AccountConfig `yaml:"wyze"`
	}
	app.LoadConfig(&v)

	accounts = v.Cfg

	log = app.GetLogger("wyze")

	gwell.DebugLog = func(msg string) {
		log.Debug().Msg(msg)
	}

	streams.HandleFunc("wyze", func(rawURL string) (core.Producer, error) {
		log.Debug().Msgf("wyze: dial %s", rawURL)
		return dialProducer(rawURL)
	})

	api.HandleFunc("api/wyze", apiWyze)
}

var cloudCache sync.Map // email -> *wyze.Cloud (login once per account)

func getCloud(email string) (*wyze.Cloud, error) {
	cfg, ok := accounts[email]
	if !ok {
		return nil, fmt.Errorf("wyze: account not found: %s", email)
	}

	if cfg.APIKey == "" || cfg.APIID == "" {
		return nil, fmt.Errorf("wyze: api_key and api_id required for account: %s", email)
	}

	if v, ok := cloudCache.Load(email); ok {
		return v.(*wyze.Cloud), nil
	}

	cloud := wyze.NewCloud(cfg.APIKey, cfg.APIID)

	if err := cloud.Login(email, cfg.Password); err != nil {
		return nil, err
	}

	cloudCache.Store(email, cloud)
	return cloud, nil
}

// dialProducer selects the protocol for a wyze:// source: explicit via the
// proto parameter, otherwise TUTK first with a Gwell fallback. GW_ hosts
// are Gwell cameras by construction and skip the doomed TUTK attempt.
func dialProducer(rawURL string) (core.Producer, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	switch u.Query().Get("proto") {
	case "gwell":
		return dialGwell(rawURL)
	case "tutk":
		return wyze.NewProducer(rawURL)
	}

	if strings.HasPrefix(strings.ToUpper(u.Hostname()), "GW_") {
		return dialGwell(rawURL)
	}

	prod, tutkErr := wyze.NewProducer(rawURL)
	if tutkErr == nil {
		return prod, nil
	}

	gwellProd, gwellErr := dialGwell(rawURL)
	if gwellErr == nil {
		return gwellProd, nil
	}

	return nil, fmt.Errorf("wyze: tutk: %v; gwell: %w", tutkErr, gwellErr)
}

// dialGwell connects to a Gwell protocol camera. Mars credentials come from
// access_id/access_token URL parameters or from a configured Wyze account.
func dialGwell(rawURL string) (core.Producer, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	host, mac, err := gwell.ParseSourceURL(rawURL)
	if err != nil {
		return nil, err
	}

	token, wakeup, err := gwellToken(rawURL, mac)
	if err != nil {
		return nil, err
	}

	lanIP := ""
	if ip := net.ParseIP(host); ip != nil {
		lanIP = host
	}

	cfg := gwell.Config{
		Token:       token,
		CameraLanIP: lanIP,
		DeviceMAC:   mac,
		OnWakeup:    wakeup,
	}
	if tid := u.Query().Get("tid"); tid != "" {
		if v, err := strconv.ParseUint(tid, 0, 64); err == nil {
			cfg.DeviceTID = v
		}
	}
	if wakeDisabled(u.Query()) {
		// peek mode: no wakeup happens (OnWakeup is nil), so don't wait
		// out the long battery-camera retry window either, and let the
		// camera sleep after it ends its live view
		cfg.CallTimeout = peekCallTimeout
		cfg.Peek = true
		if v := u.Query().Get("cooldown"); v != "" {
			d, err := parseSleepCooldown(v)
			if err != nil {
				return nil, err
			}
			cfg.SleepCooldown = d
		}
	}

	return gwell.NewProducer(cfg, rawURL)
}

// peekCallTimeout bounds the CALLING retry window in wake=0 (peek) mode:
// an already-awake camera answers within a second or two, while a sleeping
// one stays silent, so there is nothing to wait for.
const peekCallTimeout = 8 * time.Second

// parseSleepCooldown parses the cooldown= URL parameter: a Go duration
// ("90s", "2m") or a plain number of seconds ("90"). Zero disables the
// peek sleep cooldown.
func parseSleepCooldown(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		if d < 0 {
			return 0, fmt.Errorf("wyze: negative cooldown %q", s)
		}
		if d == 0 {
			return -1, nil // zero: cooldown disabled
		}
		return d, nil
	}
	secs, err := strconv.Atoi(s)
	if err != nil || secs < 0 {
		return 0, fmt.Errorf("wyze: invalid cooldown %q (use seconds, e.g. 90 or 90s)", s)
	}
	if secs == 0 {
		return -1, nil
	}
	return time.Duration(secs) * time.Second, nil
}

// wakeDisabled reports whether the source URL opts out of cloud wakeups
// ("wake=0"): connect only if the camera is already awake, e.g. from a
// motion event, and fail fast otherwise.
func wakeDisabled(query url.Values) bool {
	switch strings.ToLower(query.Get("wake")) {
	case "0", "no", "false", "off":
		return true
	}
	return false
}

// lookupCamera resolves device info with a cache: the wakeup path runs
// every ~20s during a doorbell call and must not fetch the full device
// list from the cloud API each time.
var cameraCache sync.Map // "email\x00MAC" -> *wyze.Camera

func lookupCamera(cloud *wyze.Cloud, email, bareMAC string) (*wyze.Camera, error) {
	key := email + "\x00" + bareMAC
	if v, ok := cameraCache.Load(key); ok {
		return v.(*wyze.Camera), nil
	}
	cam, err := cloud.GetCameraByMACSuffix(bareMAC)
	if err != nil {
		return nil, err
	}
	cameraCache.Store(key, cam)
	return cam, nil
}

// gwellToken resolves the Mars access token: from explicit URL parameters or
// by logging into a configured Wyze account and registering the device.
// The second return value wakes the camera (sleeping battery devices).
func gwellToken(rawURL string, mac string) (*gwell.AccessToken, func() error, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	query := u.Query()

	if id, token := query.Get("access_id"), query.Get("access_token"); id != "" && token != "" {
		t, err := gwell.ParseAccessToken(id, token)
		return t, nil, err
	}

	emails := make([]string, 0, len(accounts))
	if email := query.Get("email"); email != "" {
		emails = append(emails, email)
	} else {
		for email := range accounts {
			emails = append(emails, email)
		}
		sort.Strings(emails)
	}

	if len(emails) == 0 {
		return nil, nil, fmt.Errorf("gwell: no wyze account configured (add one to the wyze config section or pass access_id/access_token in the URL)")
	}

	// peek mode (wake=0): never send cloud wakeups, so a sleeping
	// camera is left alone and the dial fails fast instead
	noWake := wakeDisabled(query)

	var lastErr error
	for _, email := range emails {
		cloud, err := getCloud(email)
		if err != nil {
			lastErr = err
			continue
		}

		creds, err := cloud.GetGwellCredentials(mac)
		if err != nil {
			lastErr = err
			continue
		}

		token, err := gwell.ParseAccessToken(creds.AccessID, creds.AccessToken)
		if err != nil {
			lastErr = err
			continue
		}

		if noWake {
			return token, nil, nil
		}

		// wakeup closure: re-wake the (possibly sleeping) camera on demand
		wakeup := func() error {
			cam, err := lookupCamera(cloud, email, mac)
			if err != nil {
				return err
			}
			return cloud.WakeupDevice(cam.MAC, cam.ProductModel)
		}

		// best effort: wake battery powered Gwell cameras (doorbells)
		if cam, err := lookupCamera(cloud, email, mac); err == nil {
			if err := cloud.WakeupDevice(cam.MAC, cam.ProductModel); err != nil {
				log.Debug().Msgf("gwell: wakeup %s: %v", cam.MAC, err)
			} else {
				log.Debug().Msgf("gwell: wakeup sent to %s (%s)", cam.MAC, cam.ProductModel)
			}
		}

		return token, wakeup, nil
	}

	return nil, nil, lastErr
}

func apiWyze(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		apiDeviceList(w, r)
	case "POST":
		apiAuth(w, r)
	}
}

func apiDeviceList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	email := query.Get("id")
	if email == "" {
		accountList := make([]string, 0, len(accounts))
		for id := range accounts {
			accountList = append(accountList, id)
		}
		api.ResponseJSON(w, accountList)
		return
	}

	err := func() error {
		cloud, err := getCloud(email)
		if err != nil {
			return err
		}

		cameras, err := cloud.GetCameraList()
		if err != nil {
			return err
		}

		var items []*api.Source
		for _, cam := range cameras {
			items = append(items, &api.Source{
				Name: cam.Nickname,
				Info: fmt.Sprintf("%s | %s | %s", cam.ProductModel, cam.MAC, cam.IP),
				URL:  buildStreamURL(cam),
			})
		}

		api.ResponseSources(w, items)
		return nil
	}()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func apiAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := r.Form.Get("email")
	password := r.Form.Get("password")
	apiKey := r.Form.Get("api_key")
	apiID := r.Form.Get("api_id")

	if email == "" || password == "" || apiKey == "" || apiID == "" {
		http.Error(w, "email, password, api_key and api_id required", http.StatusBadRequest)
		return
	}

	// Try to login
	cloud := wyze.NewCloud(apiKey, apiID)

	if err := cloud.Login(email, password); err != nil {
		// Check for MFA error
		var authErr *wyze.AuthError
		if ok := isAuthError(err, &authErr); ok {
			w.Header().Set("Content-Type", api.MimeJSON)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(authErr)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cfg := map[string]string{
		"password": password,
		"api_key":  apiKey,
		"api_id":   apiID,
	}

	if err := app.PatchConfig([]string{"wyze", email}, cfg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if accounts == nil {
		accounts = make(map[string]AccountConfig)
	}
	accounts[email] = AccountConfig{
		APIKey:   apiKey,
		APIID:    apiID,
		Password: password,
	}

	cameras, err := cloud.GetCameraList()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var items []*api.Source
	for _, cam := range cameras {
		items = append(items, &api.Source{
			Name: cam.Nickname,
			Info: fmt.Sprintf("%s | %s | %s", cam.ProductModel, cam.MAC, cam.IP),
			URL:  buildStreamURL(cam),
		})
	}

	api.ResponseSources(w, items)
}

func buildStreamURL(cam *wyze.Camera) string {
	query := url.Values{}

	if cam.Gwell {
		// Gwell cameras: the MAC parameter carries the GW_ identifier, the
		// dialer resolves credentials from the account and matches the
		// device by its bare MAC suffix.
		query.Set("proto", "gwell")
		query.Set("mac", cam.MAC)
		query.Set("model", cam.ProductModel)
		host := cam.IP
		if host == "" {
			host = cam.MAC // relay-only: no direct LAN address
		}
		return fmt.Sprintf("wyze://%s?%s", host, query.Encode())
	}

	query.Set("uid", cam.P2PID)
	query.Set("enr", cam.ENR)
	query.Set("mac", cam.MAC)
	query.Set("model", cam.ProductModel)

	if cam.DTLS == 1 {
		query.Set("dtls", "true")
	}

	return fmt.Sprintf("wyze://%s?%s", cam.IP, query.Encode())
}

func isAuthError(err error, target **wyze.AuthError) bool {
	if e, ok := err.(*wyze.AuthError); ok {
		*target = e
		return true
	}
	return false
}
