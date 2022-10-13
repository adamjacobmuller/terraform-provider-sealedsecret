package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces
var (
	_ provider.Provider = &sealedSecretProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New() provider.Provider {
	return &sealedSecretProvider{}
}

// hashicupsProvider is the provider implementation.
type sealedSecretProvider struct{}

// Metadata returns the provider type name.
func (p *sealedSecretProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sealedsecret"
}

// GetSchema defines the provider-level schema for configuration data.
func (p *sealedSecretProvider) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Description: "Interact with HashiCups.",
	}, nil
}

// Configure prepares a HashiCups API client for data sources and resources.
func (p *sealedSecretProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Info(ctx, "Configuring HashiCups client")

	tflog.Info(ctx, "Configured HashiCups client", map[string]any{"success": true})
}

// DataSources defines the data sources implemented in the provider.
func (p *sealedSecretProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

// Resources defines the resources implemented in the provider.
func (p *sealedSecretProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSealedSecretResource,
	}
}
