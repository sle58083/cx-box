package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/sle58083/cx-box/internal/kernel"
	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
	"github.com/sle58083/cx-box/internal/sub"
	"github.com/sle58083/cx-box/web"
)

const sessionCookie = "cxbox_session"

// registerPanelRoutes 在面板路径下注册登录与管理 API。
func (s *Server) registerPanelRoutes(r *gin.Engine, panelPath string) {
	base := normalizePath(panelPath)

	r.GET(base+"/", s.panelIndex)
	r.GET(base, s.panelIndex)

	api := r.Group(base + "/api")
	api.POST("/login", s.handleLogin)
	api.POST("/logout", s.handleLogout)

	auth := api.Group("", s.authMiddleware)
	auth.GET("/status", s.handleStatus)
	auth.GET("/setting", s.handleGetSetting)
	auth.PUT("/setting", s.handleUpdateSetting)
	auth.POST("/admin/credentials", s.handleSetCredentials)
	auth.GET("/protocols", func(c *gin.Context) {
		ok(c, gin.H{"protocols": renderer.Metas(), "defaults": renderer.Defaults()})
	})
	auth.POST("/tools/reality-keypair", s.handleRealityKeypair)
	auth.POST("/tools/parse-link", s.handleParseLink)
	auth.GET("/tools/qrcode", s.handleQRCode)
	auth.POST("/apply", s.handleApply)

	auth.GET("/inbounds", s.listInbounds)
	auth.POST("/inbounds", s.createInbound)
	auth.GET("/inbounds/:id", s.getInbound)
	auth.PUT("/inbounds/:id", s.updateInbound)
	auth.DELETE("/inbounds/:id", s.deleteInbound)

	auth.GET("/outbounds", s.listOutbounds)
	auth.POST("/outbounds", s.createOutbound)
	auth.GET("/outbounds/:id", s.getOutbound)
	auth.PUT("/outbounds/:id", s.updateOutbound)
	auth.DELETE("/outbounds/:id", s.deleteOutbound)

	auth.GET("/clients", s.listClients)
	auth.POST("/clients", s.createClient)
	auth.GET("/clients/:id", s.getClient)
	auth.GET("/clients/:id/links", s.clientLinks)
	auth.PUT("/clients/:id", s.updateClient)
	auth.DELETE("/clients/:id", s.deleteClient)
	auth.POST("/clients/:id/reset-traffic", s.resetClientTraffic)

	auth.GET("/certificates", s.listCertificates)
	auth.POST("/certificates", s.createCertificate)
	auth.POST("/certificates/selfsigned", s.createSelfSigned)
	auth.DELETE("/certificates/:id", s.deleteCertificate)
}

// panelIndex 下发内嵌的面板单页应用（web/index.html，登录与管理界面）。
func (s *Server) panelIndex(c *gin.Context) {
	// 无尾斜杠访问（/app）时先跳到 /app/，保证页面内相对路径 api/... 解析正确。
	if !strings.HasSuffix(c.Request.URL.Path, "/") {
		c.Redirect(http.StatusFound, c.Request.URL.Path+"/")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", web.IndexHTML)
}

// ---- 通用响应 ----

func ok(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"data": data})
}

func fail(c *gin.Context, status int, err error) {
	c.JSON(status, gin.H{"error": err.Error()})
}

func failMsg(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

// ---- 鉴权 ----

// authMiddleware 接受三种凭据：会话 Cookie、会话 token（Bearer）、API token（Bearer 或 X-API-Token）。
func (s *Server) authMiddleware(c *gin.Context) {
	if cookie, err := c.Cookie(sessionCookie); err == nil && s.sessions.Valid(cookie) {
		c.Next()
		return
	}
	bearer := ""
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		bearer = strings.TrimPrefix(h, "Bearer ")
	}
	if bearer != "" && (s.sessions.Valid(bearer) || s.token.Verify(bearer)) {
		c.Next()
		return
	}
	if t := c.GetHeader("X-API-Token"); t != "" && s.token.Verify(t) {
		c.Next()
		return
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未登录或凭据无效"})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		failMsg(c, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if !s.admin.Verify(req.Username, req.Password) {
		failMsg(c, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	token := s.sessions.Create(req.Username)
	st, _ := s.setting.Get()
	path := "/"
	if st != nil && st.PanelPath != "" {
		path = st.PanelPath
	}
	c.SetCookie(sessionCookie, token, int(sessionTTL.Seconds()), path, "", false, true)
	ok(c, gin.H{"token": token, "username": req.Username})
}

func (s *Server) handleLogout(c *gin.Context) {
	if cookie, err := c.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(cookie)
	}
	c.SetCookie(sessionCookie, "", -1, "/", "", false, true)
	ok(c, gin.H{"logged_out": true})
}

// ---- 状态 / 设置 / 管理员 ----

func (s *Server) handleStatus(c *gin.Context) {
	st, err := s.setting.Get()
	if err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	kernelRunning := s.km != nil && s.km.Running()
	trafficUp, trafficDown, _ := s.traffic.Totals(c.Request.Context())
	ok(c, gin.H{
		"app":            "cx-box",
		"version":        Version,
		"kernel_version": kernel.DefaultVersion,
		"kernel_running": kernelRunning,
		"kernel_ready":   s.cfg != nil,
		"panel_port":     st.PanelPort,
		"panel_path":     st.PanelPath,
		"sub_port":       st.SubPort,
		"sub_path":       st.SubPath,
		"traffic_up":     trafficUp,
		"traffic_down":   trafficDown,
		"server":         collectServerStats(),
	})
}

func (s *Server) handleGetSetting(c *gin.Context) {
	st, err := s.setting.Get()
	if err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	ok(c, st)
}

func (s *Server) handleUpdateSetting(c *gin.Context) {
	var req model.Setting
	if err := c.ShouldBindJSON(&req); err != nil {
		failMsg(c, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	cur, err := s.setting.Get()
	if err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	req.ID = cur.ID
	if err := s.setting.Update(&req); err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	ok(c, gin.H{"updated": true, "note": "端口/路径修改将在重启后生效"})
}

func (s *Server) handleSetCredentials(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" || req.Password == "" {
		failMsg(c, http.StatusBadRequest, "username 与 password 必填")
		return
	}
	if err := s.admin.SetCredentials(req.Username, req.Password); err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	ok(c, gin.H{"updated": true})
}

func (s *Server) handleApply(c *gin.Context) {
	if s.cfg == nil {
		failMsg(c, http.StatusServiceUnavailable, "内核未就绪（启动时下载失败？）")
		return
	}
	if err := s.cfg.Apply(c.Request.Context()); err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	ok(c, gin.H{"applied": true})
}

// okApplied 是增删改成功后的统一响应：保存后立即应用配置，让面板修改
// 即时生效（与用户对「保存即生效」的预期一致）。曾有用户建好全部入站和
// 客户端却没点「应用配置」，内核一直跑空配置、节点全部不可用且面板毫无
// 提示——自动应用就是为消除这个坑。应用失败不回滚已保存的数据（修正后
// 再保存即可重试），但把错误以 apply_error 随响应带回，前端必须显著
// 提示，绝不静默。
func (s *Server) okApplied(c *gin.Context, data any) {
	if s.cfg == nil {
		ok(c, data)
		return
	}
	if err := s.cfg.Apply(c.Request.Context()); err != nil {
		c.JSON(http.StatusOK, gin.H{"data": data, "apply_error": "已保存，但应用配置失败：" + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "applied": true})
}

// handleParseLink 把一条分享链接解析成出站草稿（落地机导入用）：前端
// 拿到草稿后走正常的新建出站接口落库，名称冲突等校验与手工新建一致。
func (s *Server) handleParseLink(c *gin.Context) {
	var req struct {
		URI string `json:"uri"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.URI) == "" {
		failMsg(c, http.StatusBadRequest, "uri 必填")
		return
	}
	parsed, err := renderer.ParseLink(req.URI)
	if err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	ok(c, parsed)
}

// ---- 入站 CRUD ----

func (s *Server) listInbounds(c *gin.Context) {
	list, err := s.inbound.List()
	if err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	ok(c, list)
}

func (s *Server) createInbound(c *gin.Context) {
	var in model.Inbound
	if err := c.ShouldBindJSON(&in); err != nil {
		failMsg(c, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	in.ID = model.NewID()
	if err := s.inbound.Create(&in); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, in)
}

func (s *Server) getInbound(c *gin.Context) {
	in, err := s.inbound.Get(c.Param("id"))
	if err != nil {
		fail(c, http.StatusNotFound, err)
		return
	}
	ok(c, in)
}

func (s *Server) updateInbound(c *gin.Context) {
	existing, err := s.inbound.Get(c.Param("id"))
	if err != nil {
		fail(c, http.StatusNotFound, err)
		return
	}
	var in model.Inbound
	if err := c.ShouldBindJSON(&in); err != nil {
		failMsg(c, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	in.ID = existing.ID
	in.CreatedAt = existing.CreatedAt
	if err := s.inbound.Update(&in); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, in)
}

func (s *Server) deleteInbound(c *gin.Context) {
	if err := s.inbound.Delete(c.Param("id")); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, gin.H{"deleted": true})
}

// ---- 出站 CRUD ----

func (s *Server) listOutbounds(c *gin.Context) {
	list, err := s.outbound.List()
	if err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	ok(c, list)
}

func (s *Server) createOutbound(c *gin.Context) {
	var ob model.Outbound
	if err := c.ShouldBindJSON(&ob); err != nil {
		failMsg(c, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	ob.ID = model.NewID()
	if err := s.outbound.Create(&ob); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, ob)
}

func (s *Server) getOutbound(c *gin.Context) {
	ob, err := s.outbound.Get(c.Param("id"))
	if err != nil {
		fail(c, http.StatusNotFound, err)
		return
	}
	ok(c, ob)
}

func (s *Server) updateOutbound(c *gin.Context) {
	existing, err := s.outbound.Get(c.Param("id"))
	if err != nil {
		fail(c, http.StatusNotFound, err)
		return
	}
	var ob model.Outbound
	if err := c.ShouldBindJSON(&ob); err != nil {
		failMsg(c, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	ob.ID = existing.ID
	ob.CreatedAt = existing.CreatedAt
	if err := s.outbound.Update(&ob); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, ob)
}

func (s *Server) deleteOutbound(c *gin.Context) {
	if err := s.outbound.Delete(c.Param("id")); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, gin.H{"deleted": true})
}

// ---- 客户端 CRUD ----

// clientView 是管理 API 的客户端视图：含凭据字段（模型本身 json:"-" 隐藏，
// 但管理端需要看到 UUID/密码/订阅 ID 才能运维；本接口在鉴权之后）。
type clientView struct {
	model.Client
	UUID        string   `json:"uuid"`
	Password    string   `json:"password"`
	InboundIDs  []string `json:"inbound_ids"`  // 多选入站（空 = 全部用户入口）
	OutboundIDs []string `json:"outbound_ids"` // 多选出口（空 = 跟随全局默认；多选自动测速组）
}

// password 返回请求里携带的客户端密码（单独成方法，避免与模型字段同名混淆）。
func (v clientView) password() string { return v.Password }

func viewClient(cl *model.Client) clientView {
	pw := cl.Password
	ids := cl.SelectedInboundIDs()
	if ids == nil {
		ids = []string{}
	}
	return clientView{Client: *cl, UUID: cl.UUID, Password: pw, InboundIDs: ids,
		OutboundIDs: cl.SelectedOutboundIDs()}
}

// applyInboundSelection 把请求里的入站选择落到模型：inbound_ids 出现时（含空
// 数组 = 不限定）以它为准并同步旧的单选字段；未出现时保留旧单选语义。
func applyInboundSelection(cl *model.Client, req *clientView) {
	if req.InboundIDs == nil {
		return
	}
	cl.SetInboundIDs(req.InboundIDs)
	if len(req.InboundIDs) > 0 {
		first := req.InboundIDs[0]
		cl.InboundID = &first
	} else {
		cl.InboundID = nil
	}
}

// applyOutboundSelection 把请求里的出口选择落到模型：outbound_ids 出现时
// （含空数组 = 跟随全局默认）以它为准并同步旧的单选字段；未出现时保留
// 请求体里的单选 outbound_id 语义。
func applyOutboundSelection(cl *model.Client, req *clientView) {
	if req.OutboundIDs == nil {
		return
	}
	cl.SetOutboundIDs(req.OutboundIDs)
	if len(req.OutboundIDs) > 0 {
		cl.OutboundID = req.OutboundIDs[0]
	} else {
		cl.OutboundID = ""
	}
}

func (s *Server) listClients(c *gin.Context) {
	list, err := s.client.List()
	if err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	views := make([]clientView, 0, len(list))
	for i := range list {
		views = append(views, viewClient(&list[i]))
	}
	ok(c, views)
}

func (s *Server) createClient(c *gin.Context) {
	var req clientView
	if err := c.ShouldBindJSON(&req); err != nil {
		failMsg(c, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	cl := req.Client
	cl.UUID = req.UUID
	cl.Password = req.password()
	applyInboundSelection(&cl, &req)
	applyOutboundSelection(&cl, &req)
	cl.ID = model.NewID()
	if err := s.client.Create(&cl); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, viewClient(&cl))
}

func (s *Server) getClient(c *gin.Context) {
	cl, err := s.client.Get(c.Param("id"))
	if err != nil {
		fail(c, http.StatusNotFound, err)
		return
	}
	ok(c, viewClient(cl))
}

func (s *Server) updateClient(c *gin.Context) {
	existing, err := s.client.Get(c.Param("id"))
	if err != nil {
		fail(c, http.StatusNotFound, err)
		return
	}
	var req clientView
	if err := c.ShouldBindJSON(&req); err != nil {
		failMsg(c, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	cl := req.Client
	cl.ID = existing.ID
	cl.CreatedAt = existing.CreatedAt
	cl.UUID = req.UUID
	cl.Password = req.password()
	applyInboundSelection(&cl, &req)
	if req.InboundIDs == nil {
		cl.InboundIDs = existing.InboundIDs // 未携带多选字段的更新不清空已有多选
	}
	applyOutboundSelection(&cl, &req)
	if req.OutboundIDs == nil {
		cl.OutboundIDs = existing.OutboundIDs // 未携带多选字段的更新不清空已有多选
	}
	if err := s.client.Update(&cl); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, viewClient(&cl))
}

// clientLinks 返回某客户端的逐条节点链接（单个节点导出用），内容与订阅一致，
// 主机名按本次请求推导（与 /sub 下发同一套 requestHost 逻辑）。
func (s *Server) clientLinks(c *gin.Context) {
	cl, err := s.client.Get(c.Param("id"))
	if err != nil {
		fail(c, http.StatusNotFound, err)
		return
	}
	gen := sub.New(s.db)
	links, _, err := gen.Links(cl.SubID, requestHost(c))
	if err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	type nodeLink struct {
		Name string `json:"name"`
		Type string `json:"type"`
		URI  string `json:"uri"`
	}
	out := make([]nodeLink, 0, len(links))
	for _, uri := range links {
		name, typ := parseLinkMeta(uri)
		out = append(out, nodeLink{Name: name, Type: typ, URI: uri})
	}
	ok(c, out)
}

// parseLinkMeta 从分享链接提取展示用的名称与协议：名称取 # 片段（vmess 取
// base64 JSON 里的 ps），协议取 scheme（hy2 规范成 hysteria2）。
func parseLinkMeta(uri string) (string, string) {
	scheme, rest, _ := strings.Cut(uri, "://")
	typ := scheme
	if typ == "hy2" {
		typ = "hysteria2"
	}
	if typ == "ss" {
		typ = "shadowsocks"
	}
	if scheme == "vmess" {
		raw, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(rest)
		}
		if err == nil {
			var j struct {
				Ps string `json:"ps"`
			}
			if json.Unmarshal(raw, &j) == nil && j.Ps != "" {
				return j.Ps, typ
			}
		}
		return typ, typ
	}
	if i := strings.LastIndex(uri, "#"); i >= 0 && i+1 < len(uri) {
		if name, err := url.PathUnescape(uri[i+1:]); err == nil && name != "" {
			return name, typ
		}
	}
	return typ, typ
}

// resetClientTraffic 把客户端已用流量清零并重新应用：超额被生成器
// 排除的客户端会随本次应用恢复可用。
func (s *Server) resetClientTraffic(c *gin.Context) {
	cl, err := s.client.Get(c.Param("id"))
	if err != nil {
		fail(c, http.StatusNotFound, err)
		return
	}
	cl.UsedBytes = 0
	if err := s.client.Update(cl); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, cl)
}

func (s *Server) deleteClient(c *gin.Context) {
	if err := s.client.Delete(c.Param("id")); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, gin.H{"deleted": true})
}

// ---------- 证书 ----------

func (s *Server) listCertificates(c *gin.Context) {
	list, err := s.cert.List(c.Request.Context())
	if err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	ok(c, list)
}

type certImportReq struct {
	Name    string `json:"name"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func (s *Server) createCertificate(c *gin.Context) {
	var req certImportReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	cert, err := s.cert.Create(c.Request.Context(), req.Name, req.CertPEM, req.KeyPEM)
	if err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, cert)
}

type selfSignedReq struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Days    int      `json:"days"`
}

func (s *Server) createSelfSigned(c *gin.Context) {
	var req selfSignedReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	cert, err := s.cert.SelfSigned(c.Request.Context(), req.Name, req.Domains, req.Days)
	if err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, cert)
}

func (s *Server) deleteCertificate(c *gin.Context) {
	if err := s.cert.Delete(c.Request.Context(), c.Param("id")); err != nil {
		fail(c, http.StatusBadRequest, err)
		return
	}
	s.okApplied(c, gin.H{"deleted": true})
}

// handleQRCode 把 text 参数渲染成二维码 PNG（订阅导出弹窗用；
// 本地生成，不把订阅地址发给任何第三方二维码服务）。
func (s *Server) handleQRCode(c *gin.Context) {
	text := c.Query("text")
	if text == "" || len(text) > 2048 {
		failMsg(c, http.StatusBadRequest, "text 参数必填且长度不超过 2048")
		return
	}
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	c.Data(http.StatusOK, "image/png", png)
}

// handleRealityKeypair 生成一对 Reality（X25519）密钥，编码与 sing-box 一致
// （base64 RawURLEncoding）。私钥填入站 TLS，公钥供客户端/订阅使用。
func (s *Server) handleRealityKeypair(c *gin.Context) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fail(c, http.StatusInternalServerError, err)
		return
	}
	enc := base64.RawURLEncoding
	ok(c, gin.H{
		"private_key": enc.EncodeToString(priv.Bytes()),
		"public_key":  enc.EncodeToString(priv.PublicKey().Bytes()),
	})
}
