// Copied from https://github.com/gofiber/fiber
// See license https://github.com/gofiber/fiber/blob/main/LICENSE
package echox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/valyala/bytebufferpool"
)

const (
	ViewBind = "viewbind"
	UserCtx  = "userctx"
	ReqStart = "reqstart"
)

const (
	queryTag  = "query"
	headerTag = "header"
	formTag   = "form"
	paramTag  = "param"
	cookieTag = "cookie"
)

type Context struct{ echo.Context }

var _ echo.Context = (*Context)(nil)

// Append the specified value to the HTTP response header field.
// If the header is not already set, it creates the header with the specified value.
func (c *Context) Append(field string, values ...string) {
	h := c.Response().Header()
	for _, v := range values {
		h.Add(field, v)
	}
}

// Attachment sets the HTTP response Content-Disposition header field to attachment.
func (c *Context) Attachmentx(filename ...string) {
	if len(filename) == 0 {
		c.Response().Header().Set(echo.HeaderContentDisposition, "attachment")
		return
	}
	name := filepath.Base(filename[0])
	c.Context.Attachment(filename[0], name)
}

// BaseURL returns (protocol + host).
func (c *Context) BaseURL() string {
	return c.Scheme() + "://" + c.Context.Request().Host
}

// BodyRaw contains the raw body submitted in a POST request.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Context) BodyRaw() []byte {
	b, _ := io.ReadAll(c.Request().Body)
	return b
}

// Body contains the raw body submitted in a POST request.
// This method will decompress the body if the 'Content-Encoding' header is provided.
// It returns the original (or decompressed) body data which is valid only within the handler.
// Don't store direct references to the returned data.
// If you need to keep the body's data later, make a copy or use the Immutable option.
func (c *Context) Body() []byte {
	b, _ := io.ReadAll(c.Request().Body)
	return b
}

// BodyParser binds the request body to a struct.
// It supports decoding the following content types based on the Content-Type header:
// application/json, application/xml, application/x-www-form-urlencoded, multipart/form-data
// All JSON extenstion mime types are supported (eg. application/problem+json)
// If none of the content types above are matched, it will return a ErrUnprocessableEntity error
func (c *Context) BodyParser(out any) error {
	return DefaultBinder.BindBody(c, out)
}

// ClearCookie expires a specific cookie by key on the client side.
// If no key is provided it expires all cookies that came with the request.
func (c *Context) ClearCookie(key ...string) {
	for _, k := range key {
		c.SetCookie(&http.Cookie{Name: k, Value: "", Expires: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)})
	}
}

// UserContext returns a context implementation that was set by
// user earlier or returns a non-nil, empty context,if it was not set earlier.
func (c *Context) UserContext() context.Context {
	if ctx := c.Context.Get(UserCtx); ctx != nil {
		return ctx.(context.Context)
	}
	return context.Background()
}

// SetUserContext sets a context implementation by user.
func (c *Context) SetUserContext(ctx context.Context) {
	c.Context.Set(UserCtx, ctx)
}

// Cookie sets a cookie by passing a cookie struct.
func (c *Context) Cookiex(cookie *http.Cookie) {
	c.SetCookie(cookie)
}

// Cookies are used for getting a cookie value by key.
// Defaults to the empty string "" if the cookie doesn't exist.
// If a default value is given, it will return that value if the cookie doesn't exist.
// The returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (c *Context) Cookiesx(key string, defaultValue ...string) (val string) {
	if v, err := c.Context.Cookie(key); err == nil {
		val = v.Value
	}
	return defaulter(val, defaultValue...)
}

// CookieParser is used to bind cookies to a struct
func (c *Context) CookieParser(out any) error {
	data := map[string][]string{}
	for _, co := range c.Context.Cookies() {
		data[co.Name] = append(data[co.Name], co.Value)
	}
	return DefaultBinder.BindData(out, data, "cookie")
}

// Download transfers the file from path as an attachment.
// Typically, browsers will prompt the user for download.
// By default, the Content-Disposition header filename= parameter is the filepath (this typically appears in the browser dialog).
// Override this default with the filename parameter.
func (c *Context) Download(file string, filename ...string) error {
	if len(filename) == 0 {
		filename = append(filename, filepath.Base(file))
	}
	return c.Context.Attachment(file, filename[0])
}

// FormValue returns the first value by key from a MultipartForm.
// Search is performed in QueryArgs, PostArgs, MultipartForm and FormFile in this particular order.
// Defaults to the empty string "" if the form value doesn't exist.
// If a default value is given, it will return that value if the form value does not exist.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Context) FormValuex(key string, defaultValue ...string) string {
	return defaulter(c.FormValue(key), defaultValue...)
}

// Getx returns the HTTP request header specified by field.
// Field names are case-insensitive
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Context) Getx(key string, defaultValue ...string) string {
	return defaulter(c.Request().Header.Get(key), defaultValue...)
}

// GetRespHeader returns the HTTP response header specified by field.
// Field names are case-insensitive
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Context) GetRespHeader(key string, defaultValue ...string) string {
	return defaulter(c.Response().Header().Get(key), defaultValue...)
}

// GetReqHeaders returns the HTTP request headers.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Context) GetReqHeaders() map[string][]string {
	return c.Request().Header
}

// GetRespHeaders returns the HTTP response headers.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
func (c *Context) GetRespHeaders() map[string][]string {
	return c.Response().Header()
}

// Hostname contains the hostname derived from the X-Forwarded-Host or Host HTTP header.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting instead.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (c *Context) Hostname() string {
	if host := c.Getx("X-Forwarded-Host"); len(host) > 0 {
		commaPos := strings.Index(host, ",")
		if commaPos != -1 {
			return host[:commaPos]
		}
		return host
	}
	return c.Request().URL.Hostname()
}

// Port returns the remote port of the request.
func (c *Context) Port() string {
	return c.Request().URL.Port()
}

// IP returns the remote IP address of the request.
// If ProxyHeader and IP Validation is configured, it will parse that header and return the first valid IP address.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (c *Context) IP() string {
	return c.RealIP()
}

// IPs returns a string slice of IP addresses specified in the X-Forwarded-For request header.
// When IP validation is enabled, only valid IPs are returned.
func (c *Context) IPs() []string {
	return []string{c.RealIP()}
}

// JSON converts any interface or string to JSON.
// Array and slice values encode as JSON arrays,
// except that []byte encodes as a base64-encoded string,
// and a nil slice encodes as the null JSON value.
// If the ctype parameter is given, this method will set the
// Content-Type header equal to ctype. If ctype is not given,
// The Content-Type header will be set to application/json.
func (c *Context) JSONx(data any, ctype ...string) error {
	return c.Context.JSON(c.Response().Status, data)
}

// JSONP sends a JSON response with JSONP support.
// This method is identical to JSON, except that it opts-in to JSONP callback support.
// By default, the callback name is simply callback.
func (c *Context) JSONPx(data any, callback ...string) error {
	return c.Context.JSONP(c.Response().Status, append(callback, "callback")[0], data)
}

// XML converts any interface or string to XML.
// This method also sets the content header to application/xml.
func (c *Context) XMLx(data any) error {
	return c.Context.XML(c.Response().Status, data)
}

// Links joins the links followed by the property to populate the response's Link HTTP header field.
func (c *Context) Links(link ...string) {
	if len(link) == 0 {
		return
	}
	bb := bytebufferpool.Get()
	for i := range link {
		if i%2 == 0 {
			_ = bb.WriteByte('<')          //nolint:errcheck // This will never fail
			_, _ = bb.WriteString(link[i]) //nolint:errcheck // This will never fail
			_ = bb.WriteByte('>')          //nolint:errcheck // This will never fail
		} else {
			_, _ = bb.WriteString(`; rel="` + link[i] + `",`) //nolint:errcheck // This will never fail
		}
	}
	c.Response().Header().Set("Link", strings.TrimRight(bb.String(), ","))
	bytebufferpool.Put(bb)
}

// Locals makes it possible to pass any values under keys scoped to the request
// and therefore available to all following routes that match the request.
func (c *Context) Locals(key any, value ...any) any {
	if len(value) == 0 {
		return c.Context.Get(key.(string))
	}
	c.Context.Set(key.(string), value[0])
	return value[0]
}

// Location sets the response Location HTTP header to the specified path parameter.
func (c *Context) Location(path string) {
	c.Set(echo.HeaderLocation, path)
}

// Method returns the HTTP request method for the context, optionally overridden by the provided argument.
// If no override is given or if the provided override is not a valid HTTP method, it returns the current method from the context.
// Otherwise, it updates the context's method and returns the overridden method as a string.
func (c *Context) Method(override ...string) string {
	return c.Request().Method
}

// OriginalURL contains the original request URL.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (c *Context) OriginalURL() string {
	return c.Request().URL.String()
}

// Params is used to get the route parameters.
// Defaults to empty string "" if the param doesn't exist.
// If a default value is given, it will return that value if the param doesn't exist.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (c *Context) Params(key string, defaultValue ...string) string {
	return defaulter(c.Param(key), defaultValue...)
}

// AllParams Params is used to get all route parameters.
// Using Params method to get params.
func (c *Context) AllParams() map[string]string {
	names := c.ParamNames()
	params := make(map[string]string, len(names))
	for _, param := range names {
		params[param] = c.Param(param)
	}
	return params
}

// ParamsParser binds the param string to a struct.
func (c *Context) ParamsParser(out any) error {
	return DefaultBinder.BindPathParams(c, out)
}

// ParamsInt is used to get an integer from the route parameters
// it defaults to zero if the parameter is not found or if the
// parameter cannot be converted to an integer
// If a default value is given, it will return that value in case the param
// doesn't exist or cannot be converted to an integer
func (c *Context) ParamsInt(key string, defaultValue ...int) (int, error) {
	// Use Atoi to convert the param to an int or return zero and an error
	value, err := strconv.Atoi(c.Params(key))
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0], nil
		}
		return 0, fmt.Errorf("failed to convert: %w", err)
	}
	return value, nil
}

// Path returns the path part of the request URL.
// Optionally, you could override the path.
func (c *Context) Pathx(override ...string) string {
	return c.Request().URL.Path
}

// Protocol contains the request protocol string: http or https for TLS requests.
// Please use Config.EnableTrustedProxyCheck to prevent header spoofing, in case when your app is behind the proxy.
func (c *Context) Protocol() string {
	return c.Scheme()
}

// Query returns the query string parameter in the url.
// Defaults to empty string "" if the query doesn't exist.
// If a default value is given, it will return that value if the query doesn't exist.
// Returned value is only valid within the handler. Do not store any references.
// Make copies or use the Immutable setting to use the value outside the Handler.
func (c *Context) Query(key string, defaultValue ...string) string {
	return defaulter(c.QueryParam(key), defaultValue...)
}

// Queries returns a map of query parameters and their values.
//
// GET /?name=alex&wanna_cake=2&id=
// Queries()["name"] == "alex"
// Queries()["wanna_cake"] == "2"
// Queries()["id"] == ""
//
// GET /?field1=value1&field1=value2&field2=value3
// Queries()["field1"] == "value2"
// Queries()["field2"] == "value3"
//
// GET /?list_a=1&list_a=2&list_a=3&list_b[]=1&list_b[]=2&list_b[]=3&list_c=1,2,3
// Queries()["list_a"] == "3"
// Queries()["list_b[]"] == "3"
// Queries()["list_c"] == "1,2,3"
//
// GET /api/search?filters.author.name=John&filters.category.name=Technology&filters[customer][name]=Alice&filters[status]=pending
// Queries()["filters.author.name"] == "John"
// Queries()["filters.category.name"] == "Technology"
// Queries()["filters[customer][name]"] == "Alice"
// Queries()["filters[status]"] == "pending"
func (c *Context) Queries() map[string]string {
	v := map[string]string{}
	DefaultBinder.BindQueryParams(c.Context, &v)
	return v
}

// QueryInt returns integer value of key string parameter in the url.
// Default to empty or invalid key is 0.
//
//	GET /?name=alex&wanna_cake=2&id=
//	QueryInt("wanna_cake", 1) == 2
//	QueryInt("name", 1) == 1
//	QueryInt("id", 1) == 1
//	QueryInt("id") == 0
func (c *Context) QueryInt(key string, defaultValue ...int) int {
	// Use Atoi to convert the param to an int or return zero and an error
	value, err := strconv.Atoi(c.QueryParam(key))
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return 0
	}
	return value
}

// QueryBool returns bool value of key string parameter in the url.
// Default to empty or invalid key is false.
//
//	Get /?name=alex&want_pizza=false&id=
//	QueryBool("want_pizza") == false
//	QueryBool("want_pizza", true) == false
//	QueryBool("name") == false
//	QueryBool("name", true) == true
//	QueryBool("id") == false
//	QueryBool("id", true) == true
func (c *Context) QueryBool(key string, defaultValue ...bool) bool {
	value, err := strconv.ParseBool(c.QueryParam(key))
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return false
	}
	return value
}

// QueryFloat returns float64 value of key string parameter in the url.
// Default to empty or invalid key is 0.
//
//	GET /?name=alex&amount=32.23&id=
//	QueryFloat("amount") = 32.23
//	QueryFloat("amount", 3) = 32.23
//	QueryFloat("name", 1) = 1
//	QueryFloat("name") = 0
//	QueryFloat("id", 3) = 3
func (c *Context) QueryFloat(key string, defaultValue ...float64) float64 {
	// use strconv.ParseFloat to convert the param to a float or return zero and an error.
	value, err := strconv.ParseFloat(c.QueryParam(key), 64)
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return 0
	}
	return value
}

// QueryParser binds the query string to a struct.
func (c *Context) QueryParser(out any) error {
	return DefaultBinder.BindQueryParams(c.Context, &out)
}

// ReqHeaderParser binds the request header strings to a struct.
func (c *Context) ReqHeaderParser(out any) error {
	return DefaultBinder.BindHeaders(c, out)
}

var (
	ErrRangeMalformed     = errors.New("range: malformed range header string")
	ErrRangeUnsatisfiable = errors.New("range: unsatisfiable range")
)

// Redirect to the URL derived from the specified path, with specified status.
// If status is not specified, status defaults to 302 Found.
func (c *Context) Redirectx(location string, status ...int) error {
	return c.Context.Redirect(append(status, 302)[0], location)
}

// Bind Add vars to default view var map binding to template engine.
// Variables are read by the Render method and may be overwritten.
func (c *Context) Bindx(vars map[string]any) error {
	if old := c.Get(ViewBind); old != nil {
		if old, ok := old.(map[string]any); ok {
			for k, v := range old {
				vars[k] = v
			}
		}
	}
	c.Set(ViewBind, vars)
	return nil
}

// GetRouteURL generates URLs to named routes, with parameters. URLs are relative, for example: "/user/1831"
func (c *Context) GetRouteURL(routeName string, params map[string]any) (string, error) {
	vals := make([]any, len(params))
	if i := 0; len(params) > 0 {
		for _, v := range params {
			vals[i] = v
			i++
		}
	}
	return c.Context.Echo().Reverse(routeName, vals...), nil
}

// RedirectToRoute to the Route registered in the app with appropriate parameters
// If status is not specified, status defaults to 302 Found.
// If you want to send queries to route, you must add "queries" key typed as map[string]string to params.
func (c *Context) RedirectToRoute(routeName string, params map[string]any, status ...int) error {
	uri, _ := c.GetRouteURL(routeName, params)
	return c.Context.Redirect(append(status, 302)[0], uri)
}

// RedirectBack to the URL to referer
// If status is not specified, status defaults to 302 Found.
func (c *Context) RedirectBack(fallback string, status ...int) error {
	location := c.Getx("Referer")
	if location == "" {
		location = fallback
	}
	return c.Context.Redirect(status[0], location)
}

// Render a template with data and sends a text/html response.
func (c *Context) Renderx(name string, bind any, layouts ...string) error {
	name += ":" + strings.Join(layouts, ":")
	return c.Render(c.Response().Status, name, bind)
}

var emptyRoute = &echo.Route{}

func (c *Context) Route() *echo.Route {
	pathx := c.Context.Path()
	for _, r := range c.Echo().Routes() {
		if pathx == r.Path {
			return r
		}
	}
	return emptyRoute
}

// SaveFile saves any multipart file to disk.
func (c *Context) SaveFile(fileheader *multipart.FileHeader, path string) error {
	src, err := fileheader.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(path)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

type Storage interface {
	Set(path string, content []byte, expiry time.Duration) error
}

// SaveFileToStorage saves any multipart file to an external storage system.
func (*Context) SaveFileToStorage(fileheader *multipart.FileHeader, path string, storage Storage) error {
	file, err := fileheader.Open()
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}

	content, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read: %w", err)
	}

	if err := storage.Set(path, content, 0); err != nil {
		return fmt.Errorf("failed to store: %w", err)
	}

	return nil
}

// Secure returns whether a secure connection was established.
func (c *Context) Secure() bool {
	return c.Scheme() == "https"
}

// Send sets the HTTP response body without copying it.
// From this point onward the body argument must not be changed.
func (c *Context) Send(body []byte) error {
	return c.Context.Blob(c.Response().Status, c.Response().Header().Get("Content-Type"), body)
}

// SendFile transfers the file from the given path.
// The file is not compressed by default, enable this by passing a 'true' argument
// Sets the Content-Type response HTTP header field based on the filenames extension.
func (c *Context) SendFile(file string, compress ...bool) error {
	f, err := os.OpenFile(file, 0, os.ModePerm)
	if err == nil {
		b, _ := io.ReadAll(f)
		return c.Context.Blob(c.Response().Status, "", b)
	}
	return err
}

// SendStatus sets the HTTP status code and if the response body is empty,
// it sets the correct status message in the body.
func (c *Context) SendStatus(status int) error {
	c.Context.Response().Status = status
	// Only set status body when there is no response body
	if c.Response().Size == 0 {
		return c.SendString(http.StatusText(status))
	}
	return c.Send([]byte{})
}

// SendString sets the HTTP response body for string types.
// This means no type assertion, recommended for faster performance
func (c *Context) SendString(body string) error {
	return c.Context.String(c.Response().Status, body)
}

// SendStream sets response body stream and optional body size.
func (c *Context) SendStream(stream io.Reader, size ...int) error {
	return c.Context.Stream(c.Response().Status, "", stream)
}

// Set sets the response's HTTP header field to the specified key, value.
func (c *Context) Setx(key, val string) {
	c.Context.Response().Header().Set(key, val)
}

// Subdomains returns a string slice of subdomains in the domain name of the request.
// The subdomain offset, which defaults to 2, is used for determining the beginning of the subdomain segments.
func (c *Context) Subdomains(offset ...int) []string {
	o := 2
	if len(offset) > 0 {
		o = offset[0]
	}
	subdomains := strings.Split(c.Hostname(), ".")
	l := len(subdomains) - o
	// Check index to avoid slice bounds out of range panic
	if l < 0 {
		l = len(subdomains)
	}
	subdomains = subdomains[:l]
	return subdomains
}

// Status sets the HTTP status for the response.
// This method is chainable.
func (c *Context) Status(status int) *Context {
	c.Response().Status = status
	return c
}

// Type sets the Content-Type HTTP header to the MIME type specified by the file extension.
func (c *Context) Type(extension string, charset ...string) *Context {
	c.Response().Header().Set(echo.HeaderContentType, mime.TypeByExtension(extension))
	return c
}

// Vary adds the given header field to the Vary response header.
// This will append the header, if not already listed, otherwise leaves it listed in the current location.
func (c *Context) Vary(fields ...string) {
	c.Append(echo.HeaderVary, fields...)
}

// Write appends p into response body.
func (c *Context) Write(p []byte) (int, error) {
	c.Response().Write(p)
	return len(p), nil
}

// Writef appends f & a into response body writer.
func (c *Context) Writef(f string, a ...any) (int, error) {
	//nolint:wrapcheck // This must not be wrapped
	return fmt.Fprintf(c.Response().Writer, f, a...)
}

// WriteString appends s to response body.
func (c *Context) WriteString(s string) (int, error) {
	return c.Write([]byte(s))
}

// XHR returns a Boolean property, that is true, if the request's X-Requested-With header field is XMLHttpRequest,
// indicating that the request was issued by a client library (such as jQuery).
func (c *Context) XHR() bool {
	return strings.ToLower(c.Request().Header.Get(echo.HeaderXRequestedWith)) == "xmlhttprequest"
}

var trusted = func() []string {
	t := []string{}
	if tp := os.Getenv("TRUSTED_PROXIES"); tp != "" {
		t = strings.Split(tp, ",")
	}
	return t
}()

func (c *Context) IsProxyTrusted() bool {
	ip := c.Request().RemoteAddr
	for _, tp := range trusted {
		if strings.Contains(tp, ip) {
			return true
		}
	}
	return false
}

var localHosts = [...]string{"127.0.0.1", "::1", "@"}

// IsLocalHost will return true if address is a localhost address.
func (*Context) IsLocalHost(address string) bool {
	for _, h := range localHosts {
		if address == h {
			return true
		}
	}
	return false
}

// IsFromLocal will return true if request came from local.
func (c *Context) IsFromLocal() bool {
	return c.IsLocalHost(c.Request().RemoteAddr)
}

func defaulter(v string, d ...string) string {
	if v == "" && len(d) > 0 {
		return d[0]
	}
	return v
}
