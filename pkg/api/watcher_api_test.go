/*
Copyright (C) 2022-2023 Traefik Labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	hubv1alpha1 "github.com/traefik/hub-agent-kubernetes/pkg/crd/api/hub/v1alpha1"
	hubkubemock "github.com/traefik/hub-agent-kubernetes/pkg/crd/generated/client/hub/clientset/versioned/fake"
	hubinformer "github.com/traefik/hub-agent-kubernetes/pkg/crd/generated/client/hub/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

var toUpdate = &hubv1alpha1.API{
	ObjectMeta: metav1.ObjectMeta{
		Name: "toUpdate",
	},
	Spec: hubv1alpha1.APISpec{
		PathPrefix: "oldPrefix",
	},
}

var toDelete = &hubv1alpha1.API{
	ObjectMeta: metav1.ObjectMeta{
		Name: "toDelete",
	},
	Spec: hubv1alpha1.APISpec{
		PathPrefix: "oldPrefix",
	},
}

func Test_WatcherAPIRun(t *testing.T) {
	clientSetHub := hubkubemock.NewSimpleClientset([]runtime.Object{toUpdate, toDelete}...)

	ctx, cancel := context.WithCancel(context.Background())
	hubInformer := hubinformer.NewSharedInformerFactory(clientSetHub, 0)
	apiInformer := hubInformer.Hub().V1alpha1().APIs().Informer()

	hubInformer.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), apiInformer.HasSynced)

	var callCount int

	client := newPlatformClientMock(t)
	client.OnGetAPIs().
		TypedReturns([]API{
			{
				Name:       "toCreate",
				PathPrefix: "prefix",
				Service: hubv1alpha1.APIService{
					Name: "service",
					Port: hubv1alpha1.APIServiceBackendPort{
						Number: 80,
					},
				},
				Version: "1",
			},
			{
				Name:       "toUpdate",
				PathPrefix: "prefixUpdate",
				Service: hubv1alpha1.APIService{
					Name: "serviceUpdate",
					Port: hubv1alpha1.APIServiceBackendPort{
						Number: 80,
					},
				},
				Version: "2",
			},
		}, nil).
		Run(func(_ mock.Arguments) {
			callCount++
			if callCount > 1 {
				cancel()
			}
		})

	w := NewWatcherAPI(client, clientSetHub, hubInformer, time.Millisecond)
	go w.Run(ctx)

	<-ctx.Done()

	api, err := clientSetHub.HubV1alpha1().APIs("").Get(ctx, "toCreate", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "prefix", policy.Spec.PathPrefix)
	assert.Equal(t, hubv1alpha1.APIService{
		Name: "service",
		Port: hubv1alpha1.APIServiceBackendPort{
			Number: 80,
		},
	}, policy.Spec.Service)

	api, err = clientSetHub.HubV1alpha1().APIs("").Get(ctx, "toUpdate", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "prefixUpdate", policy.Spec.PathPrefix)
	assert.Equal(t, hubv1alpha1.APIService{
		Name: "serviceUpdate",
		Port: hubv1alpha1.APIServiceBackendPort{
			Number: 80,
		},
	}, policy.Spec.Service)

	_, err = clientSetHub.HubV1alpha1().APIs().Get(ctx, "toDelete", metav1.GetOptions{})
	require.Error(t, err)
}
