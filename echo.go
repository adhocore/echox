package echox

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

type HandlerFunc = func(c *Context) error

type Error struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func (e *Error) Error() string { return e.Message }

type Echo struct {
	*echo.Echo
	AutoHead bool // Get route also adds Head route
}

func New() *Echo {
	e := echo.New()
	e.Binder = DefaultBinder

	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(ReqStart, time.Now())
			return next(&Context{c})
		}
	})
	return &Echo{Echo: e}
}

func (e *Echo) Uses(m func(c *Context, next echo.HandlerFunc) error) {
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			return m(c.(*Context), next)
		}
	})
}

func (e *Echo) Delete(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add(http.MethodDelete, path, Adapt(h), m...)
}

func (e *Echo) Get(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	if e.AutoHead {
		e.Add(http.MethodHead, path, Adapt(h), m...)
	}
	return e.Add(http.MethodGet, path, Adapt(h), m...)
}

func (e *Echo) Patch(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add(http.MethodPatch, path, Adapt(h), m...)
}

func (e *Echo) Post(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add(http.MethodPost, path, Adapt(h), m...)
}

func (e *Echo) Put(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add(http.MethodPut, path, Adapt(h), m...)
}

func (e *Echo) GetPost(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	methods := []string{http.MethodGet, http.MethodPost}
	if e.AutoHead {
		methods = append(methods, http.MethodHead)
	}
	return e.Match(methods, path, Adapt(h), m...)[0]
}

func (e *Echo) Group(prefix string, m ...echo.MiddlewareFunc) (g *Group) {
	g = &Group{Group: e.Echo.Group(prefix, m...), AutoHead: e.AutoHead}
	g.Group.Use(m...)
	return
}

type Group struct {
	*echo.Group
	AutoHead bool
}

func (e *Group) Uses(m func(c *Context, next echo.HandlerFunc) error) {
	e.Group.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			return m(c.(*Context), next)
		}
	})
}

func (e *Group) Delete(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add(http.MethodDelete, path, Adapt(h), m...)
}

func (e *Group) Get(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	if e.AutoHead {
		e.Add(http.MethodHead, path, Adapt(h), m...)
	}
	return e.Add(http.MethodGet, path, Adapt(h), m...)
}

func (e *Group) Patch(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add(http.MethodPatch, path, Adapt(h), m...)
}

func (e *Group) Post(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add(http.MethodPost, path, Adapt(h), m...)
}

func (e *Group) Put(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	return e.Add(http.MethodPut, path, Adapt(h), m...)
}

func (e *Group) GetPost(path string, h HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route {
	methods := []string{http.MethodGet, http.MethodPost}
	if e.AutoHead {
		methods = append(methods, http.MethodHead)
	}
	return e.Group.Match(methods, path, Adapt(h), m...)[0]
}
