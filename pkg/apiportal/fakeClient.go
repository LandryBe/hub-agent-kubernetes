package apiportal

import "context"

type FakeClient struct {
}

func (f FakeClient) GetAPIPortal(_ context.Context) ([]ApiPortal, error) {
	return []ApiPortal{
		{
			Domain:        "domain",
			CustomDomains: nil,
			Name:          "api-portal-test",
			Services: []Service{
				{
					Name:            "openapi-write",
					Namespace:       "openapi",
					OpenApiPathPort: 8080,
					OpenAPIPath:     "/openapi-spec.yaml",
				},
				{
					Name:            "openapi-read",
					Namespace:       "openapi",
					OpenApiPathPort: 8080,
					OpenAPIPath:     "/openapi-spec.yaml",
				},
			},
		},
	}, nil
}
