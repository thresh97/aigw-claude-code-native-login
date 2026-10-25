terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# azurerm 4.x needs a subscription. Leave var.subscription_id null to use ARM_SUBSCRIPTION_ID
# or the az CLI's current subscription.
provider "azurerm" {
  subscription_id = var.subscription_id
  features {}
}
