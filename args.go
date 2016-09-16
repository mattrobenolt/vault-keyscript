package main

import (
	"fmt"
	"strings"
)

type Args map[string]string

func (a Args) Get(key string) string {
	if v, ok := a[key]; ok {
		return v
	}
	wups(fmt.Sprintf("missing required argument: %s", key))
	panic("lol")
}

// Take input in the form:
// 	key1=value;key2=value
func splitArgs(args string, sep string) Args {
	m := make(map[string]string)
	for _, bit := range strings.Split(args, sep) {
		pair := strings.SplitN(bit, "=", 2)
		m[pair[0]] = pair[1]
	}
	return Args(m)
}
