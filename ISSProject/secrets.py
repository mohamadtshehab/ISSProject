import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient


KEY_VAULT_NAME = 'filestoringapp'
KEY_VAULT_URL = f"https://{KEY_VAULT_NAME}.vault.azure.net/"

credential = DefaultAzureCredential()
client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

connection_string = client.get_secret('azure-storage-connection-string').value
account_key = client.get_secret('storage-key').value
secret_key = client.get_secret('project-secret-key').value
twilio_account_sid = client.get_secret('twilio-account-sid').value
twilio_auth_token = client.get_secret('twilio-auth-token').value
twilio_service_sid = client.get_secret('twilio-service-sid').value
