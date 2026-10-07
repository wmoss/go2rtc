package wyze

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
)

const (
	baseURLAuth = "https://auth-prod.api.wyze.com"
	baseURLAPI  = "https://api.wyzecam.com"
	appName     = "com.hualai.WyzeCam"
	appVersion  = "2.50.0"
)

// ErrAccessToken reports an expired or invalid Wyze access token; the
// caller may re-login and retry.
var ErrAccessToken = errors.New("wyze: access token error")

type Cloud struct {
	client      *http.Client
	apiKey      string
	keyID       string
	accessToken string
	userID      string
	phoneID     string
	cameras     []*Camera

	// credentials kept for automatic re-login when the token expires
	authMu   sync.Mutex
	email    string
	password string

	// per-account cache of Mars credentials, keyed by device ID
	tokensMu sync.Mutex
	tokens   map[string]*GwellCredentials
}

// Camera describes a device from the Wyze cloud list.
type Camera struct {
	MAC          string `json:"mac"`
	P2PID        string `json:"p2p_id"`
	ENR          string `json:"enr"`
	IP           string `json:"ip"`
	Nickname     string `json:"nickname"`
	ProductModel string `json:"product_model"`
	ProductType  string `json:"product_type"`
	DTLS         int    `json:"dtls"`
	FirmwareVer  string `json:"firmware_ver"`
	IsOnline     bool   `json:"is_online"`
	Gwell        bool   `json:"gwell"` // Gwell/IoTVideo protocol camera (GW_ MAC)
}

// GwellCredentials holds per-camera Mars credentials (Wyze Gwell P2P).
type GwellCredentials struct {
	AccessID    string `json:"accessId"`
	AccessToken string `json:"accessToken"`
	ExpireTime  int64  `json:"expireTime"`
}

func (c *GwellCredentials) Valid() bool {
	return c.AccessID != "" && c.AccessToken != "" && c.ExpireTime > time.Now().Unix()+3600
}

type deviceListResponse struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		DeviceList []deviceInfo `json:"device_list"`
	} `json:"data"`
}

type deviceInfo struct {
	MAC          string       `json:"mac"`
	ENR          string       `json:"enr"`
	Nickname     string       `json:"nickname"`
	ProductModel string       `json:"product_model"`
	ProductType  string       `json:"product_type"`
	FirmwareVer  string       `json:"firmware_ver"`
	ConnState    int          `json:"conn_state"`
	DeviceParams deviceParams `json:"device_params"`
}

type deviceParams struct {
	P2PID   string `json:"p2p_id"`
	P2PType int    `json:"p2p_type"`
	IP      string `json:"ip"`
	DTLS    int    `json:"dtls"`
}

type p2pInfoResponse struct {
	Code string         `json:"code"`
	Msg  string         `json:"msg"`
	Data map[string]any `json:"data"`
}

type loginResponse struct {
	AccessToken    string   `json:"access_token"`
	RefreshToken   string   `json:"refresh_token"`
	UserID         string   `json:"user_id"`
	MFAOptions     []string `json:"mfa_options"`
	SMSSessionID   string   `json:"sms_session_id"`
	EmailSessionID string   `json:"email_session_id"`
}

func NewCloud(apiKey, keyID string) *Cloud {
	return &Cloud{
		client:  &http.Client{Timeout: 30 * time.Second},
		phoneID: generatePhoneID(),
		apiKey:  apiKey,
		keyID:   keyID,
		tokens:  map[string]*GwellCredentials{},
	}
}

// Login authenticates against the Wyze cloud and remembers the
// credentials so the session can renew itself when the token expires.
func (c *Cloud) Login(email, password string) error {
	c.authMu.Lock()
	c.email = strings.TrimSpace(email)
	c.password = password
	c.authMu.Unlock()
	return c.login()
}

func (c *Cloud) login() error {
	c.authMu.Lock()
	defer c.authMu.Unlock()

	payload := map[string]string{
		"email":    c.email,
		"password": hashPassword(c.password),
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", baseURLAuth+"/api/user/login", strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Apikey", c.apiKey)
	req.Header.Set("Keyid", c.keyID)
	req.Header.Set("User-Agent", "go2rtc")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var errResp apiError
	_ = json.Unmarshal(body, &errResp)
	if errResp.hasError() {
		return fmt.Errorf("wyze: login failed (code %s): %s", errResp.code(), errResp.message())
	}

	var result loginResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("wyze: failed to parse login response (HTTP %d): %w", resp.StatusCode, err)
	}

	if len(result.MFAOptions) > 0 {
		return &AuthError{
			Message:  "MFA required",
			NeedsMFA: true,
			MFAType:  strings.Join(result.MFAOptions, ","),
		}
	}

	if result.AccessToken == "" {
		return errors.New("wyze: no access token in response")
	}

	c.accessToken = result.AccessToken
	c.userID = result.UserID

	return nil
}

func (c *Cloud) GetCameraList() ([]*Camera, error) {
	cameras, err := c.getCameraList()
	if errors.Is(err, ErrAccessToken) {
		// token expired: re-login once and retry
		if err := c.login(); err != nil {
			return nil, err
		}
		cameras, err = c.getCameraList()
	}
	return cameras, err
}

func (c *Cloud) getCameraList() ([]*Camera, error) {
	payload := map[string]any{
		"access_token":      c.accessToken,
		"phone_id":          c.phoneID,
		"app_name":          appName,
		"app_ver":           appName + "___" + appVersion,
		"app_version":       appVersion,
		"phone_system_type": 1,
		"sc":                "9f275790cab94a72bd206c8876429f3c",
		"sv":                "9d74946e652647e9b6c9d59326aef104",
		"ts":                time.Now().UnixMilli(),
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", baseURLAPI+"/app/v2/home_page/get_object_list", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result deviceListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("wyze: failed to parse device list: %w", err)
	}

	if result.Code != "1" {
		if result.Code == "2001" {
			return nil, fmt.Errorf("%w: %s", ErrAccessToken, result.Msg)
		}
		return nil, fmt.Errorf("wyze: API error: %s - %s", result.Code, result.Msg)
	}

	c.cameras = nil
	for _, dev := range result.Data.DeviceList {
		if dev.ProductType != "Camera" {
			continue
		}
		isGwell := strings.HasPrefix(dev.MAC, "GW_")
		if !isGwell && dev.DeviceParams.IP == "" {
			continue // skip cameras without IP (non-gwell)
		}

		c.cameras = append(c.cameras, &Camera{
			MAC:          dev.MAC,
			P2PID:        dev.DeviceParams.P2PID,
			ENR:          dev.ENR,
			IP:           dev.DeviceParams.IP,
			Nickname:     dev.Nickname,
			ProductModel: dev.ProductModel,
			ProductType:  dev.ProductType,
			DTLS:         dev.DeviceParams.DTLS,
			FirmwareVer:  dev.FirmwareVer,
			IsOnline:     dev.ConnState == 1,
			Gwell:        isGwell,
		})
	}

	return c.cameras, nil
}

func (c *Cloud) GetCamera(id string) (*Camera, error) {
	if c.cameras == nil {
		if _, err := c.GetCameraList(); err != nil {
			return nil, err
		}
	}

	id = strings.ToUpper(id)
	for _, cam := range c.cameras {
		if strings.ToUpper(cam.MAC) == id || strings.EqualFold(cam.Nickname, id) {
			return cam, nil
		}
	}

	return nil, fmt.Errorf("wyze: camera not found: %s", id)
}

func (c *Cloud) GetP2PInfo(mac string) (map[string]any, error) {
	info, err := c.getP2PInfo(mac)
	if errors.Is(err, ErrAccessToken) {
		if err := c.login(); err != nil {
			return nil, err
		}
		info, err = c.getP2PInfo(mac)
	}
	return info, err
}

func (c *Cloud) getP2PInfo(mac string) (map[string]any, error) {
	payload := map[string]any{
		"access_token":      c.accessToken,
		"phone_id":          c.phoneID,
		"device_mac":        mac,
		"app_name":          appName,
		"app_ver":           appName + "___" + appVersion,
		"app_version":       appVersion,
		"phone_system_type": 1,
		"sc":                "9f275790cab94a72bd206c8876429f3c",
		"sv":                "9d74946e652647e9b6c9d59326aef104",
		"ts":                time.Now().UnixMilli(),
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", baseURLAPI+"/app/v2/device/get_iotc_info", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result p2pInfoResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.Code != "1" {
		if result.Code == "2001" {
			return nil, fmt.Errorf("%w: %s", ErrAccessToken, result.Msg)
		}
		return nil, fmt.Errorf("wyze: API error: %s - %s", result.Code, result.Msg)
	}

	return result.Data, nil
}

type apiError struct {
	Code        string `json:"code"`
	ErrorCode   int    `json:"errorCode"`
	Msg         string `json:"msg"`
	Description string `json:"description"`
}

func (e *apiError) hasError() bool {
	if e.Code == "1" || e.Code == "0" {
		return false
	}
	if e.Code == "" && e.ErrorCode == 0 {
		return false
	}
	return e.Code != "" || e.ErrorCode != 0
}

func (e *apiError) message() string {
	if e.Msg != "" {
		return e.Msg
	}
	return e.Description
}

func (e *apiError) code() string {
	if e.Code != "" {
		return e.Code
	}
	return fmt.Sprintf("%d", e.ErrorCode)
}

type AuthError struct {
	Message  string `json:"message"`
	NeedsMFA bool   `json:"needs_mfa,omitempty"`
	MFAType  string `json:"mfa_type,omitempty"`
}

func (e *AuthError) Error() string {
	return e.Message
}

func generatePhoneID() string {
	return core.RandString(16, 16) // 16 hex chars
}

func hashPassword(password string) string {
	encoded := strings.TrimSpace(password)
	if strings.HasPrefix(strings.ToLower(encoded), "md5:") {
		return encoded[4:]
	}
	for range 3 {
		hash := md5.Sum([]byte(encoded))
		encoded = hex.EncodeToString(hash[:])
	}
	return encoded
}

const (
	baseURLMars  = "https://wyze-mars-service.wyzecam.com"
	pathMarsUser = "/plugin/mars/v2/regist_gw_user/"

	iotAppID     = "9319141212m2ik"
	iotAppSecret = "wyze_app_secret_key_132"
	iotAppName   = "com.hualai"
	iotAppVer    = "3.13.0.784"
)

// RegisterGwellUser requests per-camera Mars credentials for the Gwell P2P
// protocol (valid for 7 days). deviceID is the device MAC as reported by the
// Wyze cloud (GW_ identifiers or bare MAC).
func (c *Cloud) RegisterGwellUser(deviceID string) (*GwellCredentials, error) {
	cred, err := c.registerGwellUser(deviceID)
	if errors.Is(err, ErrAccessToken) {
		if err := c.login(); err != nil {
			return nil, err
		}
		cred, err = c.registerGwellUser(deviceID)
	}
	return cred, err
}

func (c *Cloud) registerGwellUser(deviceID string) (*GwellCredentials, error) {
	c.tokensMu.Lock()
	if cred, ok := c.tokens[deviceID]; ok && cred.Valid() {
		defer c.tokensMu.Unlock()
		return cred, nil
	}
	c.tokensMu.Unlock()

	if c.accessToken == "" {
		return nil, fmt.Errorf("wyze: login required for gwell access")
	}

	body := map[string]any{
		"ttl_minutes": 10080,
		"nonce":       fmt.Sprintf("%d", time.Now().UnixMilli()),
		"unique_id":   c.phoneID,
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", baseURLMars+pathMarsUser+deviceID, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("appid", iotAppID)
	req.Header.Set("access_token", c.accessToken)
	req.Header.Set("Authorization", c.accessToken)
	req.Header.Set("appinfo", iotAppName+"_android_"+iotAppVer)
	req.Header.Set("app_version", "android_"+iotAppVer)
	req.Header.Set("phoneid", c.phoneID)
	req.Header.Set("requestid", md5hex(md5hex(fmt.Sprintf("%d", time.Now().UnixMilli()))))
	req.Header.Set("Signature2", signature2(c.accessToken, string(bodyBytes)))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wyze: mars: http status %d (%s)",
			resp.StatusCode, strings.TrimSpace(string(respBody[:minInt(len(respBody), 120)])))
	}

	var result struct {
		Code any `json:"code"`
		Data struct {
			// Mars sends camelCase or snake_case depending on endpoint version
			AccessID      string `json:"accessId"`
			AccessIDAlt   string `json:"access_id"`
			AccessToken   string `json:"accessToken"`
			AccessTokenAl string `json:"access_token"`
			ExpireTime    int64  `json:"expireTime"`
			ExpireTimeAl  int64  `json:"expire_time"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("wyze: mars: parse response: %w", err)
	}

	switch code := result.Code.(type) {
	case float64:
		if code == 2001 {
			return nil, fmt.Errorf("%w: mars: %s", ErrAccessToken, "token rejected")
		}
		if code == 1008 {
			return nil, fmt.Errorf("wyze: mars: device %s is not registered with the Gwell service (is it a TUTK camera?)", deviceID)
		}
		if code != 1 {
			return nil, fmt.Errorf("wyze: mars: error code %v", code)
		}
	case string:
		if code == "2001" {
			return nil, fmt.Errorf("%w: mars: %s", ErrAccessToken, "token rejected")
		}
		if code == "1008" {
			return nil, fmt.Errorf("wyze: mars: device %s is not registered with the Gwell service (is it a TUTK camera?)", deviceID)
		}
		if code != "1" {
			return nil, fmt.Errorf("wyze: mars: error code %s", code)
		}
	}

	accessID := result.Data.AccessID
	if accessID == "" {
		accessID = result.Data.AccessIDAlt
	}
	accessToken := result.Data.AccessToken
	if accessToken == "" {
		accessToken = result.Data.AccessTokenAl
	}
	expireTime := result.Data.ExpireTime
	if expireTime == 0 {
		expireTime = result.Data.ExpireTimeAl
	}

	if accessID == "" || accessToken == "" {
		return nil, fmt.Errorf("wyze: mars: no credentials in response")
	}

	cred := &GwellCredentials{
		AccessID:    accessID,
		AccessToken: accessToken,
		ExpireTime:  expireTime,
	}
	if cred.ExpireTime == 0 {
		cred.ExpireTime = time.Now().Add(7 * 24 * time.Hour).Unix()
	}
	c.tokensMu.Lock()
	c.tokens[deviceID] = cred
	c.tokensMu.Unlock()

	return cred, nil
}

// GetGwellCredentials resolves Mars credentials for a camera identified by
// its bare MAC (12 hex chars). It finds the device in the account list
// (matching GW_ identifiers ending with the MAC) and registers a Mars user.
func (c *Cloud) GetGwellCredentials(bareMAC string) (*GwellCredentials, error) {
	bareMAC = strings.ToUpper(strings.ReplaceAll(bareMAC, ":", ""))

	c.tokensMu.Lock()
	if cred, ok := c.tokens[bareMAC]; ok && cred.Valid() {
		defer c.tokensMu.Unlock()
		return cred, nil
	}
	c.tokensMu.Unlock()

	cam, err := c.GetCameraByMACSuffix(bareMAC)
	if err != nil {
		return nil, err
	}
	return c.RegisterGwellUser(cam.MAC)
}

// GetCameraByMACSuffix finds a camera whose cloud MAC ends with the given
// bare MAC (matches both bare MACs and GW_ identifiers).
func (c *Cloud) GetCameraByMACSuffix(bareMAC string) (*Camera, error) {
	cameras, err := c.GetCameraList()
	if err != nil {
		return nil, err
	}

	bareMAC = strings.ToUpper(strings.ReplaceAll(bareMAC, ":", ""))
	for _, cam := range cameras {
		if strings.HasSuffix(strings.ToUpper(cam.MAC), bareMAC) {
			return cam, nil
		}
	}

	return nil, fmt.Errorf("wyze: camera with MAC %s not found on the account", bareMAC)
}

// WakeupDevice sends the wakeup-live-view action to a (possibly sleeping)
// battery powered Gwell camera, mirroring the vendor app flow.
func (c *Cloud) WakeupDevice(mac, productModel string) error {
	err := c.wakeupDevice(mac, productModel)
	if errors.Is(err, ErrAccessToken) {
		if err := c.login(); err != nil {
			return err
		}
		err = c.wakeupDevice(mac, productModel)
	}
	return err
}

func (c *Cloud) wakeupDevice(mac, productModel string) error {
	if c.accessToken == "" {
		return fmt.Errorf("wyze: login required for wakeup")
	}

	function := map[string]any{
		"name":      "wakeup",
		"separator": "::",
		"in":        map[string]any{"wakeup-live-view": 1},
	}
	capability := map[string]any{
		"iid":       "",
		"name":      "iot-device",
		"functions": []any{function},
	}
	target := map[string]any{
		"capabilities": []any{capability},
		"targetInfo": map[string]any{
			"id":           mac,
			"productModel": productModel,
			"type":         "DEVICE",
		},
		"userId": c.userID,
	}
	body := map[string]any{
		"nonce":         fmt.Sprintf("%d", time.Now().UnixMilli()),
		"targetDevices": []any{target},
		"userId":        c.userID,
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", "https://devicemgmt-service.wyze.com/device-management/api/action/run_action_batch", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("appid", iotAppID)
	req.Header.Set("access_token", c.accessToken)
	req.Header.Set("Authorization", c.accessToken)
	req.Header.Set("appinfo", iotAppName+"_android_"+iotAppVer)
	req.Header.Set("app_version", "android_"+iotAppVer)
	req.Header.Set("phoneid", c.phoneID)
	req.Header.Set("requestid", md5hex(md5hex(fmt.Sprintf("%d", time.Now().UnixMilli()))))
	req.Header.Set("Signature2", signature2(c.accessToken, string(bodyBytes)))

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body2, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("wyze: wakeup: HTTP %d: %s", resp.StatusCode, string(body2))
	}

	// the action API reports business errors in the body with HTTP 200
	var result struct {
		Code    any    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body2, &result); err == nil {
		switch code := result.Code.(type) {
		case float64:
			if code == 2001 {
				return fmt.Errorf("%w: wakeup: %s", ErrAccessToken, result.Message)
			}
			if code != 1 {
				return fmt.Errorf("wyze: wakeup: code %v: %s", code, result.Message)
			}
		case string:
			if code == "2001" {
				return fmt.Errorf("%w: wakeup: %s", ErrAccessToken, result.Message)
			}
			if code != "1" {
				return fmt.Errorf("wyze: wakeup: code %s: %s", code, result.Message)
			}
		}
	}

	return nil
}

func md5hex(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func signature2(accessToken, body string) string {
	key := md5hex(accessToken + iotAppSecret)
	mac := hmac.New(md5.New, []byte(key))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
