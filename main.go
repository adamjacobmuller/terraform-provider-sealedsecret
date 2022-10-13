package main

import (
	"context"
	"github.com/AdamJacobMuller/terraform-provider-sealedsecret/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// Provider documentation generation.
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name hashicups

func main() {
	err := providerserver.Serve(context.Background(), provider.New, providerserver.ServeOpts{
		Address: "registry.terraform.io/adamjacobmuller/sealedsecret",
	})
	if err != nil {
		panic(err)
	}
}
