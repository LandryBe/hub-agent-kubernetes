package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/runtime"
	kubemock "k8s.io/client-go/kubernetes/fake"
)

func TestWatcher_CanWatch(t *testing.T) {
	kubeObjects := []runtime.Object{}
	kubeClientSet := kubemock.NewSimpleClientset(kubeObjects...)
	assert.False(t, IsAvailable(kubeClientSet))

	kubeObjects = []runtime.Object{
		apiextensions.CustomResourceDefinition{
			Spec: apiextensions.CustomResourceDefinitionSpec{
				Names: apiextensions.CustomResourceDefinitionNames{
					Kind: "Calalog",
				},
			},
		},
	}
	kubeClientSet = kubemock.NewSimpleClientset(kubeObjects...)
	assert.True(t, IsAvailable(kubeClientSet))
}
