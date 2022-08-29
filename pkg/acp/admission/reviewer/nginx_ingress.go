package reviewer

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-kubernetes/pkg/acp"
	"github.com/traefik/hub-agent-kubernetes/pkg/acp/admission/ingclass"
	admv1 "k8s.io/api/admission/v1"
)

// NginxIngress is a reviewer that handles Nginx Ingress resources.
type NginxIngress struct {
	agentAddress   string
	ingressClasses IngressClasses
	policies       PolicyGetter
}

// NewNginxIngress returns an Nginx ingress reviewer.
func NewNginxIngress(authServerAddr string, ingClasses IngressClasses, policies PolicyGetter) *NginxIngress {
	return &NginxIngress{
		agentAddress:   authServerAddr,
		ingressClasses: ingClasses,
		policies:       policies,
	}
}

// CanReview returns whether this reviewer can handle the given admission review request.
func (r NginxIngress) CanReview(ar admv1.AdmissionReview) (bool, error) {
	resource := ar.Request.Kind

	// Check resource type. Only continue if it's a legacy Ingress (<1.18) or an Ingress resource.
	if !isNetV1Ingress(resource) && !isNetV1Beta1Ingress(resource) && !isExtV1Beta1Ingress(resource) {
		return false, nil
	}

	obj := ar.Request.Object.Raw
	if ar.Request.Operation == admv1.Delete {
		obj = ar.Request.OldObject.Raw
	}

	ingClassName, ingClassAnno, err := parseIngressClass(obj)
	if err != nil {
		return false, fmt.Errorf("parse raw ingress class: %w", err)
	}

	if ingClassName != "" {
		ctrlr, err := r.ingressClasses.GetController(ingClassName)
		if err != nil {
			return false, fmt.Errorf("get ingress class controller from ingress class name: %w", err)
		}

		return isNginx(ctrlr), nil
	}

	if ingClassAnno != "" {
		if ingClassAnno == defaultAnnotationNginx {
			return true, nil
		}

		// Don't return an error if it's the default value of another reviewer,
		// just say we can't review it.
		if isDefaultIngressClassValue(ingClassAnno) {
			return false, nil
		}

		ctrlr, err := r.ingressClasses.GetController(ingClassAnno)
		if err != nil {
			return false, fmt.Errorf("get ingress class controller from annotation: %w", err)
		}

		return isNginx(ctrlr), nil
	}

	defaultCtrlr, err := r.ingressClasses.GetDefaultController()
	if err != nil {
		return false, fmt.Errorf("get default ingress class controller: %w", err)
	}

	return isNginx(defaultCtrlr), nil
}

// Review reviews the given admission review request and optionally returns the required patch.
func (r NginxIngress) Review(ctx context.Context, ar admv1.AdmissionReview) (map[string]interface{}, error) {
	l := log.Ctx(ctx).With().Str("reviewer", "NginxIngress").Logger()
	ctx = l.WithContext(ctx)

	log.Ctx(ctx).Info().Msg("Reviewing Ingress resource")

	if ar.Request.Operation == admv1.Delete {
		log.Ctx(ctx).Info().Msg("Deleting Ingress resource")
		return nil, nil
	}

	ing, oldIng, err := parseRawIngresses(ar.Request.Object.Raw, ar.Request.OldObject.Raw)
	if err != nil {
		return nil, fmt.Errorf("parse raw objects: %w", err)
	}

	prevPolName := oldIng.Metadata.Annotations[AnnotationHubAuth]
	polName := ing.Metadata.Annotations[AnnotationHubAuth]

	if prevPolName == "" && polName == "" {
		log.Ctx(ctx).Debug().Msg("No ACP defined")
		return nil, nil
	}

	var snippets nginxSnippets
	if polName == "" {
		log.Ctx(ctx).Debug().Msg("No ACP annotation found")
	} else {
		log.Ctx(ctx).Debug().Str("acp_name", polName).Msg("ACP annotation is present")

		var polCfg *acp.Config
		polCfg, err = r.policies.GetConfig(polName)
		if err != nil {
			return nil, err
		}

		snippets, err = genSnippets(polName, polCfg, r.agentAddress)
		if err != nil {
			return nil, err
		}
	}
	snippets = mergeSnippets(snippets, ing.Metadata.Annotations)

	if noNginxPatchRequired(ing.Metadata.Annotations, snippets) {
		log.Ctx(ctx).Debug().Str("acp_name", polName).Msg("No patch required")
		return nil, nil
	}

	setNginxAnnotations(ing.Metadata.Annotations, snippets)

	log.Ctx(ctx).Info().Str("acp_name", polName).Msg("Patching resource")

	return map[string]interface{}{
		"op":    "replace",
		"path":  "/metadata/annotations",
		"value": ing.Metadata.Annotations,
	}, nil
}

func noNginxPatchRequired(anno map[string]string, snippets nginxSnippets) bool {
	return anno["nginx.ingress.kubernetes.io/configuration-snippet"] == snippets.ConfigurationSnippet &&
		anno["nginx.ingress.kubernetes.io/server-snippet"] == snippets.ServerSnippet &&
		anno["nginx.ingress.kubernetes.io/auth-url"] == snippets.AuthURL &&
		anno["nginx.ingress.kubernetes.io/auth-signin"] == snippets.AuthSignin &&
		anno["nginx.ingress.kubernetes.io/auth-snippet"] == snippets.AuthSnippet
}

func setNginxAnnotations(anno map[string]string, snippets nginxSnippets) {
	anno["nginx.ingress.kubernetes.io/auth-signin"] = snippets.AuthSignin
	anno["nginx.ingress.kubernetes.io/auth-snippet"] = snippets.AuthSnippet
	anno["nginx.ingress.kubernetes.io/auth-url"] = snippets.AuthURL
	anno["nginx.ingress.kubernetes.io/configuration-snippet"] = snippets.ConfigurationSnippet
	anno["nginx.ingress.kubernetes.io/server-snippet"] = snippets.ServerSnippet

	clearEmptyAnnotations(anno)
}

func clearEmptyAnnotations(anno map[string]string) {
	if anno["nginx.org/server-snippets"] == "" {
		delete(anno, "nginx.org/server-snippets")
	}
	if anno["nginx.org/location-snippets"] == "" {
		delete(anno, "nginx.org/location-snippets")
	}
	if anno["nginx.ingress.kubernetes.io/auth-url"] == "" {
		delete(anno, "nginx.ingress.kubernetes.io/auth-url")
	}
	if anno["nginx.ingress.kubernetes.io/configuration-snippet"] == "" {
		delete(anno, "nginx.ingress.kubernetes.io/configuration-snippet")
	}
	if anno["nginx.ingress.kubernetes.io/auth-signin"] == "" {
		delete(anno, "nginx.ingress.kubernetes.io/auth-signin")
	}
	if anno["nginx.ingress.kubernetes.io/auth-snippet"] == "" {
		delete(anno, "nginx.ingress.kubernetes.io/auth-snippet")
	}
}

func isNginx(ctrlr string) bool {
	return ctrlr == ingclass.ControllerTypeNginxCommunity
}
