package provider

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/AdamJacobMuller/terraform-provider-sealedsecret/internal/k8s"
	"github.com/AdamJacobMuller/terraform-provider-sealedsecret/internal/kubeseal"
	"github.com/AdamJacobMuller/terraform-provider-sealedsecret/internal/provider/attribute_plan_modifier"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	name          = "name"
	namespace     = "namespace"
	secretType    = "type"
	data          = "data"
	stringData    = "string_data"
	filepath      = "filepath"
	publicKeyHash = "public_key_hash"
)
const (
	username     = "username"
	token        = "token"
	url          = "url"
	sourceBranch = "source_branch"
	targetBranch = "target_branch"
)

type SealedSecret struct {
	Spec struct {
		EncryptedData map[string]string `yaml:"encryptedData"`
		Template      struct {
			Type     string `yaml:"type"`
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type sealedSecretResource struct{}

type sealedSecretModel struct {
	Name         types.String `tfsdk:"name"`
	Namespace    types.String `tfsdk:"namespace"`
	SecretType   types.String `tfsdk:"type"`
	StringData   types.Map    `tfsdk:"string_data"`
	Data         types.Map    `tfsdk:"data"`
	PublicKey    types.String `tfsdk:"public_key"`
	SealedSecret types.String `tfsdk:"sealed_secret"`
}

func NewSealedSecretResource() resource.Resource {
	return &sealedSecretResource{}
}

func (r *sealedSecretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "sealedsecret"
}

func (r *sealedSecretResource) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			name: {
				Type:        types.StringType,
				Required:    true,
				Description: "name of the secret, must be unique",
			},
			namespace: {
				Type:        types.StringType,
				Required:    true,
				Description: "namespace of the secret",
			},
			secretType: {
				Type:     types.StringType,
				Computed: true,
				Optional: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					resource.RequiresReplace(),
					attribute_plan_modifier.DefaultValue(types.String{Value: "Opaque"}),
				},
				Description: "The secret type (ex. Opaque)",
			},
			data: {
				Type: types.MapType{
					ElemType: types.StringType,
				},
				Optional:    true,
				Sensitive:   true,
				Description: "Key/value pairs to populate the secret. The value will be base64 encoded",
			},
			stringData: {
				Type: types.MapType{
					ElemType: types.StringType,
				},
				Optional:    true,
				Sensitive:   true,
				Description: "Key/value pairs to populate the secret.",
			},
			"public_key": {
				Type:        types.StringType,
				Required:    true,
				Sensitive:   false,
				Description: "The public key hashed to detect if the public key changes.",
			},
			"sealed_secret": {
				Type:        types.StringType,
				Computed:    true,
				Sensitive:   false,
				Description: "The public key hashed to detect if the public key changes.",
			},
		},
	}, nil
}

func tfMaptoMapStringString(tfMap types.Map) (map[string]string, error) {
	m := make(map[string]string)
	for k, v := range tfMap.Elems {
		m[k] = v.(types.String).Value
	}
	return m, nil
}

func (r *sealedSecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Error(ctx, "Create sealed secret resource")
	var plan sealedSecretModel

	diags := req.Plan.Get(ctx, &plan)

	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	data, err := tfMaptoMapStringString(plan.Data)
	if err != nil {
		diags.AddError("Failed to convert data tf map to map[string]string", err.Error())
		return
	}
	stringData, err := tfMaptoMapStringString(plan.StringData)
	if err != nil {
		diags.AddError("Failed to convert stringdata tf map to map[string]string", err.Error())
		return
	}

	sealedSecret, err := createSealedSecret(ctx, plan.Name.Value, plan.Namespace.Value, plan.SecretType.Value, plan.PublicKey.Value, data, stringData)
	if err != nil {
		diags.AddError("Failed to seal secret", err.Error())
		return
	}

	plan.SealedSecret = types.String{Value: string(sealedSecret)}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sealedSecretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	tflog.Error(ctx, "Read sealed secret resource")
	return
}

func (r *sealedSecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	tflog.Error(ctx, "Update sealed secret resource")
	var plan sealedSecretModel

	diags := req.Plan.Get(ctx, &plan)

	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	data, err := tfMaptoMapStringString(plan.Data)
	if err != nil {
		diags.AddError("Failed to convert data tf map to map[string]string", err.Error())
		return
	}
	stringData, err := tfMaptoMapStringString(plan.StringData)
	if err != nil {
		diags.AddError("Failed to convert stringdata tf map to map[string]string", err.Error())
		return
	}

	sealedSecret, err := createSealedSecret(ctx, plan.Name.Value, plan.Namespace.Value, plan.SecretType.Value, plan.PublicKey.Value, data, stringData)
	if err != nil {
		diags.AddError("Failed to seal secret", err.Error())
		return
	}

	plan.SealedSecret = types.String{Value: string(sealedSecret)}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sealedSecretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	tflog.Error(ctx, "Delete sealed secret resource")
	return
}

func createSealedSecret(ctx context.Context, name, namespace, secretType, publicKey string, data, stringData map[string]string) ([]byte, error) {
	rawSecret := k8s.SecretManifest{
		Name:      name,
		Namespace: namespace,
		Type:      secretType,
	}

	rawSecret.Data = make(map[string]interface{})
	for k, v := range data {
		rawSecret.Data[k] = v
	}
	m := make(map[string]string)
	for k, v := range stringData {
		m[k] = v
	}
	rawSecret.StringData = m

	secret, err := k8s.CreateSecret(&rawSecret)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(publicKey))
	cert, _ := x509.ParseCertificate(block.Bytes)
	pk := cert.PublicKey.(*rsa.PublicKey)

	return kubeseal.SealSecret(secret, pk)
}
