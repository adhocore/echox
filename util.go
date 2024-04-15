package echox

import "github.com/labstack/echo/v4"

func Merge[K comparable, V any](maps ...map[K]V) map[K]V {
	if l := len(maps); l == 0 {
		panic("merge: empty maps list")
	} else if l == 1 {
		return maps[0]
	}
	for i := range maps {
		if i > 0 {
			for k := range maps[i] {
				maps[0][k] = maps[i][k]
			}
		}
	}
	return maps[0]
}

func Adapt(h HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		return h(c.(*Context))
	}
}
