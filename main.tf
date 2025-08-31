terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = "f2e26c0b-8b27-4edd-b6f4-73edc39a4186"
  client_id       = "d47fb118-5c46-4069-801d-a7c945665e0f"
  client_secret   = "NkG8Q~.FzKAZCNttyqvHxAwaeero5ciRepXKDa6Z"
  tenant_id       = "1172494f-68e2-4743-8ebb-b6916a1c681e"
}

resource "azurerm_security_center_connector" "gcp_connector" {
  name                = "gcp-poc-connector"
  resource_group_name = "kpmg-testing"
  location            = "eastus"
  hierarchy_identifier = "93604753456"
  environment_name    = "GCP"
  
  organizational_data {
    organization_membership_type = "Organization"
    organization_id              = "1044632980853"
    workload_identity_pool_id    = "1172494f68e247438ebbb6916a1c681e"
  }

  offering {
    offering_type = "CspmMonitorGcp"
    
    native_cloud_connection {
      workload_identity_provider_id = "cspm"
      service_account_email_address = "microsoft-defender-cspm@gcp-containers-dso-prod-189401.iam.gserviceaccount.com"
    }
  }
}
