package apiportal

import (
	"fmt"
	"testing"
)

func Test_plop(t *testing.T) {
	a := fmt.Sprintf("http://%s./%s.cluster.local:%d/%s", "name", "ns", 8080, "openapi")

	fmt.Println(a)
}
