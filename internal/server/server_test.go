package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/db"
	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/service"
)

func testServer(t *testing.T) (*Server, *gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(g); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := service.NewAdminService(g).EnsureDefault(); err != nil {
		t.Fatalf("ensure admin: %v", err)
	}
	s := New(g, nil, nil)
	r := gin.New()
	s.registerPanelRoutes(r, "/app/")
	s.registerSubRoutes(r, "/sub/")
	return s, r, g
}

func do(r *gin.Engine, method, path, body, token string) *httptest.ResponseRecorder {
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func dataField(t *testing.T, w *httptest.ResponseRecorder) json.RawMessage {
	t.Helper()
	var env struct {
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("bad json %q: %v", w.Body.String(), err)
	}
	if env.Error != "" {
		t.Fatalf("api error: %s (body %s)", env.Error, w.Body.String())
	}
	return env.Data
}

func TestPanelIndexServesSPA(t *testing.T) {
	_, r, _ := testServer(t)
	// /app（无尾斜杠）应跳转到 /app/，保证相对路径解析正确
	w := do(r, "GET", "/app", "", "")
	if w.Code != http.StatusFound {
		t.Fatalf("GET /app = %d, want 302", w.Code)
	}
	w = do(r, "GET", "/app/", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /app/ = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"cx-box", "loginForm", "view-inbounds", "view-clients"} {
		if !strings.Contains(body, want) {
			t.Fatalf("panel html missing %q", want)
		}
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %s", ct)
	}
}

func TestPanelAPIFlow(t *testing.T) {
	_, r, g := testServer(t)

	// 未登录访问受保护接口 → 401
	if w := do(r, "GET", "/app/api/status", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d", w.Code)
	}
	// 错误密码 → 401
	if w := do(r, "POST", "/app/api/login", `{"username":"admin","password":"wrong"}`, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", w.Code)
	}
	// 正确登录（默认 admin/admin）
	w := do(r, "POST", "/app/api/login", `{"username":"admin","password":"admin"}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d body %s", w.Code, w.Body.String())
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(dataField(t, w), &login); err != nil || login.Token == "" {
		t.Fatalf("login token missing: %v", err)
	}

	// 状态
	w = do(r, "GET", "/app/api/status", "", login.Token)
	var status struct {
		KernelReady bool `json:"kernel_ready"`
		PanelPort   int  `json:"panel_port"`
	}
	if err := json.Unmarshal(dataField(t, w), &status); err != nil {
		t.Fatal(err)
	}
	if status.PanelPort != 2095 || status.KernelReady {
		t.Fatalf("status = %+v", status)
	}

	// 建入站
	w = do(r, "POST", "/app/api/inbounds",
		`{"name":"vless-main","type":"vless","port":443,"is_user_inbound":true}`, login.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("create inbound = %d body %s", w.Code, w.Body.String())
	}
	var in model.Inbound
	if err := json.Unmarshal(dataField(t, w), &in); err != nil || in.Name != "vless-main" {
		t.Fatalf("inbound = %+v err %v", in, err)
	}
	// 非法协议 → 400
	if w := do(r, "POST", "/app/api/inbounds", `{"name":"bad","type":"nope","port":1}`, login.Token); w.Code != http.StatusBadRequest {
		t.Fatalf("bad protocol = %d", w.Code)
	}

	// 建客户端（自动生成 uuid/sub_id）
	w = do(r, "POST", "/app/api/clients", `{"email":"u@example.com","enable":true}`, login.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("create client = %d body %s", w.Code, w.Body.String())
	}
	var cv clientView
	if err := json.Unmarshal(dataField(t, w), &cv); err != nil {
		t.Fatal(err)
	}
	if cv.UUID == "" || cv.SubID == "" {
		t.Fatalf("client view missing generated fields: %+v", cv)
	}

	// 订阅下发（无需登录）：默认 base64，解码后应含 vless 链接
	req := httptest.NewRequest("GET", "/sub/"+cv.SubID, nil)
	req.Host = "example.com:2096"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sub = %d body %s", rec.Code, rec.Body.String())
	}
	decoded, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatalf("sub body not base64: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://") || !strings.Contains(string(decoded), "@example.com:443") {
		t.Fatalf("sub links = %s", decoded)
	}
	if rec.Header().Get("Subscription-Userinfo") == "" {
		t.Fatal("missing Subscription-Userinfo header")
	}
	// 不存在的订阅 → 404
	if w := do(r, "GET", "/sub/nope", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown sub = %d", w.Code)
	}

	// API token 鉴权：建 token 后可用 Bearer 访问（/apiv2 兼容路径）
	tok, err := service.NewTokenService(g).Create("test")
	if err != nil {
		t.Fatalf("create api token: %v", err)
	}
	if w := do(r, "GET", "/app/api/status", "", tok); w.Code != http.StatusOK {
		t.Fatalf("api-token status = %d", w.Code)
	}
}
