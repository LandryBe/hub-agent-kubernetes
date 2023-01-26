package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime"
	kubemock "k8s.io/client-go/kubernetes/fake"
)

func TestWatcher_IsAvailable(t *testing.T) {
	kubeObjects := []runtime.Object{
		// apiextensions.CustomResourceDefinition{},
	}
	kubeClientSet := kubemock.NewSimpleClientset(kubeObjects...)
	assert.False(t, IsAvailable(kubeClientSet))
}
