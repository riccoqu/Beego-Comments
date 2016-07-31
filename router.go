// Copyright 2014 beego Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package beego

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	beecontext "github.com/astaxie/beego/context"
	"github.com/astaxie/beego/toolbox"
	"github.com/astaxie/beego/utils"
)

// default filter execution points
const (
	BeforeStatic = iota
	BeforeRouter
	BeforeExec
	AfterExec
	FinishRouter
)

const (
	routerTypeBeego = iota //一般路由
	routerTypeRESTFul      //RESTFul路由
	routerTypeHandler      //Handler路由
)

var (
	// HTTP模块支持的方法
	HTTPMETHOD = map[string]string{
		"GET":     "GET",
		"POST":    "POST",
		"PUT":     "PUT",
		"DELETE":  "DELETE",
		"PATCH":   "PATCH",
		"OPTIONS": "OPTIONS",
		"HEAD":    "HEAD",
		"TRACE":   "TRACE",
		"CONNECT": "CONNECT",
	}
	// these beego.Controller's methods shouldn't reflect to AutoRouter
	exceptMethod = []string{"Init", "Prepare", "Finish", "Render", "RenderString",
		"RenderBytes", "Redirect", "Abort", "StopRun", "UrlFor", "ServeJSON", "ServeJSONP",
		"ServeXML", "Input", "ParseForm", "GetString", "GetStrings", "GetInt", "GetBool",
		"GetFloat", "GetFile", "SaveToFile", "StartSession", "SetSession", "GetSession",
		"DelSession", "SessionRegenerateID", "DestroySession", "IsAjax", "GetSecureCookie",
		"SetSecureCookie", "XsrfToken", "CheckXsrfCookie", "XsrfFormHtml",
		"GetControllerAndAction", "ServeFormatted"}

	urlPlaceholder = "{{placeholder}}"
	// DefaultAccessLogFilter will skip the accesslog if return true
	DefaultAccessLogFilter FilterHandler = &logFilter{}
)

// FilterHandler is an interface for
type FilterHandler interface {
	Filter(*beecontext.Context) bool
}

// default log filter static file will not show
type logFilter struct {
}

func (l *logFilter) Filter(ctx *beecontext.Context) bool {
	requestPath := path.Clean(ctx.Request.URL.Path)
	if requestPath == "/favicon.ico" || requestPath == "/robots.txt" {
		return true
	}
	for prefix := range BConfig.WebConfig.StaticDir {
		if strings.HasPrefix(requestPath, prefix) {
			return true
		}
	}
	return false
}

// ExceptMethodAppend to append a slice's value into "exceptMethod", for controller's methods shouldn't reflect to AutoRouter
func ExceptMethodAppend(action string) {
	exceptMethod = append(exceptMethod, action)
}
// 保存用户自定义的 Controller的结构体
type controllerInfo struct {
	pattern        string
	controllerType reflect.Type
	methods        map[string]string
	handler        http.Handler
	runFunction    FilterFunc
	routerType     int
}

// Controller包含已经注册的路由规则，handle函数和文件过滤
// Controller是一个注册器,外部调用的API例如 beego.Router()就是向它注册路由
type ControllerRegister struct {
	routers      map[string]*Tree		//路由表
	enableFilter bool			//标志位,是否有过滤器
	filters      map[int][]*FilterRouter	//文件过滤
	pool         sync.Pool			//对象池
}

// 返回一个 ControllerRegister实例
func NewControllerRegister() *ControllerRegister {
	cr := &ControllerRegister{
		routers: make(map[string]*Tree),
		filters: make(map[int][]*FilterRouter),
	}
	cr.pool.New = func() interface{} {
		return beecontext.NewContext()
	}
	return cr
}

// Add controller handler and pattern rules to ControllerRegister.
// usage:
//	default methods is the same name as method
//	Add("/user",&UserController{})
//	Add("/api/list",&RestController{},"*:ListFood")
//	Add("/api/create",&RestController{},"post:CreateFood")
//	Add("/api/update",&RestController{},"put:UpdateFood")
//	Add("/api/delete",&RestController{},"delete:DeleteFood")
//	Add("/api",&RestController{},"get,post:ApiFunc"
//	Add("/simple",&SimpleController{},"get:GetFunc;post:PostFunc")
func (p *ControllerRegister) Add(pattern string, c ControllerInterface, mappingMethods ...string) {
	reflectVal := reflect.ValueOf(c)	//反射获得 value
	t := reflect.Indirect(reflectVal).Type()//反射获得 type
	methods := make(map[string]string)
	if len(mappingMethods) > 0 {
		semi := strings.Split(mappingMethods[0], ";")//切分出每个以';'分隔的自定义方法和对应的函数
		for _, v := range semi {
			colon := strings.Split(v, ":")//切分出以':'分隔的方法名和对应的函数,colon[1]为处理的函数名
			if len(colon) != 2 {
				panic("method mapping format is invalid")
			}
			comma := strings.Split(colon[0], ",")//切分出以','分隔的方法名, comma包含了当前需要注册的所有方法名
			for _, m := range comma {
				if _, ok := HTTPMETHOD[strings.ToUpper(m)]; m == "*" || ok {
					//如果方法名为通配符'*'或者在支持的方法列表中.并使用反射包中的方法获得一个绑定对应函数的　Value类型
					//如果返回的值有效,就将当前方法加入到 methods中
					if val := reflectVal.MethodByName(colon[1]); val.IsValid() {
						methods[strings.ToUpper(m)] = colon[1]
					} else {
						//不支持方法时报错
						panic("'" + colon[1] + "' method doesn't exist in the controller " + t.Name())
					}
				} else {
					panic(v + " is an invalid method mapping. Method doesn't exist " + m)
				}
			}
		}
	}
	//添加 ControllerInfo类型来保存此项路由规则
	route := &controllerInfo{}
	route.pattern = pattern
	route.methods = methods
	route.routerType = routerTypeBeego
	route.controllerType = t
	//当传入的方法名为空时,给当前模式加入所有支持的方法
	if len(methods) == 0 {
		for _, m := range HTTPMETHOD {
			p.addToRouter(m, pattern, route)
		}
	} else {
		//方法名不为空时,判断是否含有通配符 "*"
		for k := range methods {
			if k == "*" {
				for _, m := range HTTPMETHOD {
					//含有通配符,加入所有方法
					p.addToRouter(m, pattern, route)
				}
			} else {
				//只加入指定的方法
				p.addToRouter(k, pattern, route)
			}
		}
	}
}

func (p *ControllerRegister) addToRouter(method, pattern string, r *controllerInfo) {
	if !BConfig.RouterCaseSensitive {
		pattern = strings.ToLower(pattern)
	}
	if t, ok := p.routers[method]; ok {
		//如果方法对应的路由树存在就直接添加
		t.AddRouter(pattern, r)
	} else {
		//方法不存在这新创建一个路由树
		t := NewTree()
		t.AddRouter(pattern, r)
		//设定新方法的路由树
		p.routers[method] = t
	}
}

// Include only when the Runmode is dev will generate router file in the router/auto.go from the controller
// Include(&BankAccount{}, &OrderController{},&RefundController{},&ReceiptController{})
func (p *ControllerRegister) Include(cList ...ControllerInterface) {
	if BConfig.RunMode == DEV {
		skip := make(map[string]bool, 10)
		for _, c := range cList {
			reflectVal := reflect.ValueOf(c)
			t := reflect.Indirect(reflectVal).Type()
			gopath := os.Getenv("GOPATH")
			if gopath == "" {
				panic("you are in dev mode. So please set gopath")
			}
			pkgpath := ""

			wgopath := filepath.SplitList(gopath)
			for _, wg := range wgopath {
				wg, _ = filepath.EvalSymlinks(filepath.Join(wg, "src", t.PkgPath()))
				if utils.FileExists(wg) {
					pkgpath = wg
					break
				}
			}
			if pkgpath != "" {
				if _, ok := skip[pkgpath]; !ok {
					skip[pkgpath] = true
					parserPkg(pkgpath, t.PkgPath())
				}
			}
		}
	}
	for _, c := range cList {
		reflectVal := reflect.ValueOf(c)
		t := reflect.Indirect(reflectVal).Type()
		key := t.PkgPath() + ":" + t.Name()
		if comm, ok := GlobalControllerRouter[key]; ok {
			for _, a := range comm {
				p.Add(a.Router, c, strings.Join(a.AllowHTTPMethods, ",")+":"+a.Method)
			}
		}
	}
}

// Get add get method
// usage:
//    Get("/", func(ctx *context.Context){
//          ctx.Output.Body("hello world")
//    })
func (p *ControllerRegister) Get(pattern string, f FilterFunc) {
	p.AddMethod("get", pattern, f)
}

// Post add post method
// usage:
//    Post("/api", func(ctx *context.Context){
//          ctx.Output.Body("hello world")
//    })
func (p *ControllerRegister) Post(pattern string, f FilterFunc) {
	p.AddMethod("post", pattern, f)
}

// Put add put method
// usage:
//    Put("/api/:id", func(ctx *context.Context){
//          ctx.Output.Body("hello world")
//    })
func (p *ControllerRegister) Put(pattern string, f FilterFunc) {
	p.AddMethod("put", pattern, f)
}

// Delete add delete method
// usage:
//    Delete("/api/:id", func(ctx *context.Context){
//          ctx.Output.Body("hello world")
//    })
func (p *ControllerRegister) Delete(pattern string, f FilterFunc) {
	p.AddMethod("delete", pattern, f)
}

// Head add head method
// usage:
//    Head("/api/:id", func(ctx *context.Context){
//          ctx.Output.Body("hello world")
//    })
func (p *ControllerRegister) Head(pattern string, f FilterFunc) {
	p.AddMethod("head", pattern, f)
}

// Patch add patch method
// usage:
//    Patch("/api/:id", func(ctx *context.Context){
//          ctx.Output.Body("hello world")
//    })
func (p *ControllerRegister) Patch(pattern string, f FilterFunc) {
	p.AddMethod("patch", pattern, f)
}

// Options add options method
// usage:
//    Options("/api/:id", func(ctx *context.Context){
//          ctx.Output.Body("hello world")
//    })
func (p *ControllerRegister) Options(pattern string, f FilterFunc) {
	p.AddMethod("options", pattern, f)
}

// Any add all method
// usage:
//    Any("/api/:id", func(ctx *context.Context){
//          ctx.Output.Body("hello world")
//    })
func (p *ControllerRegister) Any(pattern string, f FilterFunc) {
	p.AddMethod("*", pattern, f)
}

// AddMethod add http method router
// usage:
//    AddMethod("get","/api/:id", func(ctx *context.Context){
//          ctx.Output.Body("hello world")
//    })
/*
 * AddMethod向 ControllerRegister添加特定的方法和路由规则
 */
func (p *ControllerRegister) AddMethod(method, pattern string, f FilterFunc) {
	method = strings.ToUpper(method)
	if _, ok := HTTPMETHOD[method]; method != "*" && !ok {
		panic("not support http method: " + method)
	}
	route := &controllerInfo{}
	route.pattern = pattern
	route.routerType = routerTypeRESTFul
	route.runFunction = f
	methods := make(map[string]string)
	if method == "*" {
		//遇到通配符 "*"时,添加所有的方法
		for _, val := range HTTPMETHOD {
			methods[val] = val
		}
	} else {
		//　不是通配符只添加制定的方法
		methods[method] = method
	}
	route.methods = methods
	for k := range methods {
		if k == "*" {
			for _, m := range HTTPMETHOD {
				p.addToRouter(m, pattern, route)
			}
		} else {
			p.addToRouter(k, pattern, route)
		}
	}
}

// Handler add user defined Handler
//添加默认路由
func (p *ControllerRegister) Handler(pattern string, h http.Handler, options ...interface{}) {
	route := &controllerInfo{}
	route.pattern = pattern
	route.routerType = routerTypeHandler
	route.handler = h
	if len(options) > 0 {
		if _, ok := options[0].(bool); ok {
			pattern = path.Join(pattern, "?:all(.*)")
		}
	}
	for _, m := range HTTPMETHOD {
		p.addToRouter(m, pattern, route)
	}
}

// AddAuto router to ControllerRegister.
// example beego.AddAuto(&MainContorlller{}),
// MainController has method List and Page.
// visit the url /main/list to execute List function
// /main/page to execute Page function.
//添加自动路由
func (p *ControllerRegister) AddAuto(c ControllerInterface) {
	p.AddAutoPrefix("/", c)
}

// AddAutoPrefix Add auto router to ControllerRegister with prefix.
// example beego.AddAutoPrefix("/admin",&MainContorlller{}),
// MainController has method List and Page.
// visit the url /admin/main/list to execute List function
// /admin/main/page to execute Page function.
//添加自动路由
func (p *ControllerRegister) AddAutoPrefix(prefix string, c ControllerInterface) {
	reflectVal := reflect.ValueOf(c)
	rt := reflectVal.Type()
	ct := reflect.Indirect(reflectVal).Type()
	controllerName := strings.TrimSuffix(ct.Name(), "Controller")
	for i := 0; i < rt.NumMethod(); i++ {
		if !utils.InSlice(rt.Method(i).Name, exceptMethod) {
			route := &controllerInfo{}
			route.routerType = routerTypeBeego
			route.methods = map[string]string{"*": rt.Method(i).Name}
			route.controllerType = ct
			pattern := path.Join(prefix, strings.ToLower(controllerName), strings.ToLower(rt.Method(i).Name), "*")
			patternInit := path.Join(prefix, controllerName, rt.Method(i).Name, "*")
			patternFix := path.Join(prefix, strings.ToLower(controllerName), strings.ToLower(rt.Method(i).Name))
			patternFixInit := path.Join(prefix, controllerName, rt.Method(i).Name)
			route.pattern = pattern
			for _, m := range HTTPMETHOD {
				p.addToRouter(m, pattern, route)
				p.addToRouter(m, patternInit, route)
				p.addToRouter(m, patternFix, route)
				p.addToRouter(m, patternFixInit, route)
			}
		}
	}
}

// InsertFilter Add a FilterFunc with pattern rule and action constant.
// The bool params is for setting the returnOnOutput value (false allows multiple filters to execute)
func (p *ControllerRegister) InsertFilter(pattern string, pos int, filter FilterFunc, params ...bool) error {

	mr := new(FilterRouter)
	mr.tree = NewTree()
	mr.pattern = pattern
	mr.filterFunc = filter
	if !BConfig.RouterCaseSensitive {
		pattern = strings.ToLower(pattern)
	}
	if len(params) == 0 {
		mr.returnOnOutput = true
	} else {
		mr.returnOnOutput = params[0]
	}
	mr.tree.AddRouter(pattern, true)
	return p.insertFilterRouter(pos, mr)
}

// add Filter into
func (p *ControllerRegister) insertFilterRouter(pos int, mr *FilterRouter) error {
	p.filters[pos] = append(p.filters[pos], mr)
	p.enableFilter = true
	return nil
}

// URLFor does another controller handler in this request function.
// it can access any controller method.
func (p *ControllerRegister) URLFor(endpoint string, values ...interface{}) string {
	paths := strings.Split(endpoint, ".")
	if len(paths) <= 1 {
		Warn("urlfor endpoint must like path.controller.method")
		return ""
	}
	if len(values)%2 != 0 {
		Warn("urlfor params must key-value pair")
		return ""
	}
	params := make(map[string]string)
	if len(values) > 0 {
		key := ""
		for k, v := range values {
			if k%2 == 0 {
				key = fmt.Sprint(v)
			} else {
				params[key] = fmt.Sprint(v)
			}
		}
	}
	controllName := strings.Join(paths[:len(paths)-1], "/")
	methodName := paths[len(paths)-1]
	for m, t := range p.routers {
		ok, url := p.geturl(t, "/", controllName, methodName, params, m)
		if ok {
			return url
		}
	}
	return ""
}

func (p *ControllerRegister) geturl(t *Tree, url, controllName, methodName string, params map[string]string, httpMethod string) (bool, string) {
	for _, subtree := range t.fixrouters {
		u := path.Join(url, subtree.prefix)
		ok, u := p.geturl(subtree, u, controllName, methodName, params, httpMethod)
		if ok {
			return ok, u
		}
	}
	if t.wildcard != nil {
		u := path.Join(url, urlPlaceholder)
		ok, u := p.geturl(t.wildcard, u, controllName, methodName, params, httpMethod)
		if ok {
			return ok, u
		}
	}
	for _, l := range t.leaves {
		if c, ok := l.runObject.(*controllerInfo); ok {
			if c.routerType == routerTypeBeego &&
				strings.HasSuffix(path.Join(c.controllerType.PkgPath(), c.controllerType.Name()), controllName) {
				find := false
				if _, ok := HTTPMETHOD[strings.ToUpper(methodName)]; ok {
					if len(c.methods) == 0 {
						find = true
					} else if m, ok := c.methods[strings.ToUpper(methodName)]; ok && m == strings.ToUpper(methodName) {
						find = true
					} else if m, ok = c.methods["*"]; ok && m == methodName {
						find = true
					}
				}
				if !find {
					for m, md := range c.methods {
						if (m == "*" || m == httpMethod) && md == methodName {
							find = true
						}
					}
				}
				if find {
					if l.regexps == nil {
						if len(l.wildcards) == 0 {
							return true, strings.Replace(url, "/"+urlPlaceholder, "", 1) + toURL(params)
						}
						if len(l.wildcards) == 1 {
							if v, ok := params[l.wildcards[0]]; ok {
								delete(params, l.wildcards[0])
								return true, strings.Replace(url, urlPlaceholder, v, 1) + toURL(params)
							}
							return false, ""
						}
						if len(l.wildcards) == 3 && l.wildcards[0] == "." {
							if p, ok := params[":path"]; ok {
								if e, isok := params[":ext"]; isok {
									delete(params, ":path")
									delete(params, ":ext")
									return true, strings.Replace(url, urlPlaceholder, p+"."+e, -1) + toURL(params)
								}
							}
						}
						canskip := false
						for _, v := range l.wildcards {
							if v == ":" {
								canskip = true
								continue
							}
							if u, ok := params[v]; ok {
								delete(params, v)
								url = strings.Replace(url, urlPlaceholder, u, 1)
							} else {
								if canskip {
									canskip = false
									continue
								}
								return false, ""
							}
						}
						return true, url + toURL(params)
					}
					var i int
					var startreg bool
					regurl := ""
					for _, v := range strings.Trim(l.regexps.String(), "^$") {
						if v == '(' {
							startreg = true
							continue
						} else if v == ')' {
							startreg = false
							if v, ok := params[l.wildcards[i]]; ok {
								delete(params, l.wildcards[i])
								regurl = regurl + v
								i++
							} else {
								break
							}
						} else if !startreg {
							regurl = string(append([]rune(regurl), v))
						}
					}
					if l.regexps.MatchString(regurl) {
						ps := strings.Split(regurl, "/")
						for _, p := range ps {
							url = strings.Replace(url, urlPlaceholder, p, 1)
						}
						return true, url + toURL(params)
					}
				}
			}
		}
	}

	return false, ""
}

func (p *ControllerRegister) execFilter(context *beecontext.Context, pos int, urlPath string) (started bool) {
	if p.enableFilter {
		if l, ok := p.filters[pos]; ok {
			for _, filterR := range l {
				if filterR.returnOnOutput && context.ResponseWriter.Started {
					return true
				}
				if ok := filterR.ValidRouter(urlPath, context); ok {
					filterR.filterFunc(context)
				}
				if filterR.returnOnOutput && context.ResponseWriter.Started {
					return true
				}
			}
		}
	}
	return false
}

// 实现了 http.Handler接口
// 这个方法很重要,在 app.go文件中启动 app.Server.ServeHttp()后,接收到的 http请求都会调用此函数
func (p *ControllerRegister) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	var (
		runRouter  reflect.Type
		findRouter bool//是否找到路由
		runMethod  string
		routerInfo *controllerInfo
	)
	context := p.pool.Get().(*beecontext.Context)//beecontext就是 "github.com/astaxie/beego/context"包的别名
	context.Reset(rw, r)

	defer p.pool.Put(context)
	defer p.recoverPanic(context)

	context.Output.EnableGzip = BConfig.EnableGzip
	// 如果是开发模式则返回服务器名
	if BConfig.RunMode == DEV {
		context.Output.Header("Server", BConfig.ServerName)
	}

	var urlPath string
	// 路由大小写敏感
	if !BConfig.RouterCaseSensitive {
		urlPath = strings.ToLower(r.URL.Path)
	} else {
		urlPath = r.URL.Path
	}

	// 检查请求中的方法是否支持
	if _, ok := HTTPMETHOD[r.Method]; !ok {
		// 不支持则返回405状态
		http.Error(rw, "Method Not Allowed", 405)
		// 记录
		goto Admin
	}

	// 检查对应 url的静态文件过滤器
	if p.execFilter(context, BeforeStatic, urlPath) {
		goto Admin
	}
	// 查找静态路由
	serverStaticRouter(context)
	if context.ResponseWriter.Started {
		//路由找到并且发送了相应则修改 findRouter标志位并且跳转到记录
		findRouter = true
		goto Admin
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		if BConfig.CopyRequestBody && !context.Input.IsUpload() {
			context.Input.CopyBody(BConfig.MaxMemory)
		}
		context.Input.ParseFormOrMulitForm(BConfig.MaxMemory)
	}

	// session init
	if BConfig.WebConfig.Session.SessionOn {
		var err error
		context.Input.CruSession, err = GlobalSessions.SessionStart(rw, r)
		if err != nil {
			Error(err)
			exception("503", context)
			return
		}
		defer func() {
			if context.Input.CruSession != nil {
				context.Input.CruSession.SessionRelease(rw)
			}
		}()
	}
	//检查 Router
	if p.execFilter(context, BeforeRouter, urlPath) {
		goto Admin
	}
	//开始查找路由的过程
	if !findRouter {
		httpMethod := r.Method
		if t, ok := p.routers[httpMethod]; ok {
			runObject := t.Match(urlPath, context)
			if r, ok := runObject.(*controllerInfo); ok {
				routerInfo = r
				findRouter = true
				if splat := context.Input.Param(":splat"); splat != "" {
					for k, v := range strings.Split(splat, "/") {
						context.Input.SetParam(strconv.Itoa(k), v)
					}
				}
			}
		}

	}

	// 如果程序执行到这里还没有找到路由则抛出一个异常并跳转到记录
	if !findRouter {
		exception("404", context)
		goto Admin
	}
	//找到了路由,进行动作
	if findRouter {
		//执行中间件的过滤器
		if p.execFilter(context, BeforeExec, urlPath) {
			goto Admin
		}
		isRunnable := false
		if routerInfo != nil {
			//RESTFul路由,执行对应的方法
			if routerInfo.routerType == routerTypeRESTFul {
				if _, ok := routerInfo.methods[r.Method]; ok {
					isRunnable = true
					routerInfo.runFunction(context)
				} else {
					exception("405", context)
					goto Admin
				}
			} else if routerInfo.routerType == routerTypeHandler {
				//Handler类型的路由
				isRunnable = true
				routerInfo.handler.ServeHTTP(rw, r)
			} else {
				//其他类型的路由
				runRouter = routerInfo.controllerType
				method := r.Method
				if r.Method == "POST" && context.Input.Query("_method") == "PUT" {
					method = "PUT"
				}
				if r.Method == "POST" && context.Input.Query("_method") == "DELETE" {
					method = "DELETE"
				}
				if m, ok := routerInfo.methods[method]; ok {
					runMethod = m
				} else if m, ok = routerInfo.methods["*"]; ok {
					runMethod = m
				} else {
					runMethod = method
				}
			}
		}

		// also defined runRouter & runMethod from filter
		if !isRunnable {
			//Invoke the request handler
			vc := reflect.New(runRouter)
			execController, ok := vc.Interface().(ControllerInterface)
			if !ok {
				panic("controller is not ControllerInterface")
			}

			//call the controller init function
			execController.Init(context, runRouter.Name(), runMethod, vc.Interface())

			//call prepare function
			execController.Prepare()

			//if XSRF is Enable then check cookie where there has any cookie in the  request's cookie _csrf
			if BConfig.WebConfig.EnableXSRF {
				execController.XSRFToken()
				if r.Method == "POST" || r.Method == "DELETE" || r.Method == "PUT" ||
					(r.Method == "POST" && (context.Input.Query("_method") == "DELETE" || context.Input.Query("_method") == "PUT")) {
					execController.CheckXSRFCookie()
				}
			}

			execController.URLMapping()

			if !context.ResponseWriter.Started {
				//exec main logic
				switch runMethod {
				case "GET":
					execController.Get()
				case "POST":
					execController.Post()
				case "DELETE":
					execController.Delete()
				case "PUT":
					execController.Put()
				case "HEAD":
					execController.Head()
				case "PATCH":
					execController.Patch()
				case "OPTIONS":
					execController.Options()
				default:
					if !execController.HandlerFunc(runMethod) {
						var in []reflect.Value
						method := vc.MethodByName(runMethod)
						method.Call(in)
					}
				}

				//render template
				if !context.ResponseWriter.Started && context.Output.Status == 0 {
					if BConfig.WebConfig.AutoRender {
						if err := execController.Render(); err != nil {
							panic(err)
						}
					}
				}
			}

			// finish all runRouter. release resource
			execController.Finish()
		}

		//execute middleware filters
		if p.execFilter(context, AfterExec, urlPath) {
			goto Admin
		}
	}

	p.execFilter(context, FinishRouter, urlPath)

/*
 * 记录此次请求的一些信息
 */
Admin:
	timeDur := time.Since(startTime)
	//admin module record QPS
	if BConfig.Listen.EnableAdmin {
		if FilterMonitorFunc(r.Method, r.URL.Path, timeDur) {
			if runRouter != nil {
				go toolbox.StatisticsMap.AddStatistics(r.Method, r.URL.Path, runRouter.Name(), timeDur)
			} else {
				go toolbox.StatisticsMap.AddStatistics(r.Method, r.URL.Path, "", timeDur)
			}
		}
	}

	if BConfig.RunMode == DEV || BConfig.Log.AccessLogs {
		var devInfo string
		if findRouter {
			if routerInfo != nil {
				devInfo = fmt.Sprintf("| % -10s | % -40s | % -16s | % -10s | % -40s |", r.Method, r.URL.Path, timeDur.String(), "match", routerInfo.pattern)
			} else {
				devInfo = fmt.Sprintf("| % -10s | % -40s | % -16s | % -10s |", r.Method, r.URL.Path, timeDur.String(), "match")
			}
		} else {
			devInfo = fmt.Sprintf("| % -10s | % -40s | % -16s | % -10s |", r.Method, r.URL.Path, timeDur.String(), "notmatch")
		}
		if DefaultAccessLogFilter == nil || !DefaultAccessLogFilter.Filter(context) {
			Debug(devInfo)
		}
	}

	// Call WriteHeader if status code has been set changed
	if context.Output.Status != 0 {
		context.ResponseWriter.WriteHeader(context.Output.Status)
	}
}
// 恢复 Panic,只在 router.go:616 中被调用
func (p *ControllerRegister) recoverPanic(context *beecontext.Context) {
	if err := recover(); err != nil {
		if err == ErrAbort {
			return
		}
		if !BConfig.RecoverPanic {
			panic(err)
		} else {
			if BConfig.EnableErrorsShow {
				if _, ok := ErrorMaps[fmt.Sprint(err)]; ok {
					exception(fmt.Sprint(err), context)
					return
				}
			}
			var stack string
			Critical("the request url is ", context.Input.URL())
			Critical("Handler crashed with error", err)
			for i := 1; ; i++ {
				_, file, line, ok := runtime.Caller(i)
				if !ok {
					break
				}
				Critical(fmt.Sprintf("%s:%d", file, line))
				stack = stack + fmt.Sprintln(fmt.Sprintf("%s:%d", file, line))
			}
			if BConfig.RunMode == DEV {
				showErr(err, context, stack)
			}
		}
	}
}

//将 params拼接成 URL
func toURL(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	u := "?"
	for k, v := range params {
		u += k + "=" + v + "&"
	}
	return strings.TrimRight(u, "&")
}
