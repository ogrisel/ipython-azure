#!/usr/bin/env python

import re
import os
import sys
import logging
import time

from azure import WindowsAzureConflictError
from azure import WindowsAzureMissingResourceError
from azure import WindowsAzureError
from azure.servicemanagement import ServiceManagementService
from azure.servicemanagement import OSVirtualHardDisk
from azure.servicemanagement import LinuxConfigurationSet
from azure.storage import BlobService


FORMAT = '%(levelname)-8s %(asctime)-15s %(message)s'
logging.basicConfig(level=logging.INFO, format=FORMAT)

log = logging.getLogger()

subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
location = os.environ.get('AZURE_DEFAULT_LOCATION', 'West US')
role_size = os.environ.get('AZURE_DEFAULT_ROLE_SIZE', 'Small')

# Choose the latest ubuntu from sms.list_os_images()
image_name = None

certificate_path = os.path.expanduser('~/mycert.pem')

# Connect to the Azure platform and check that the location is valid
log.info("Checking availability of location: '%s'", location)
sms = ServiceManagementService(subscription_id, certificate_path)
assert location in [l.name for l in sms.list_locations()]

# Provision an hosted service
service_name = sys.argv[1]
affinity_group = service_name
target_blob_name = service_name + ".vhd"
service_label = service_name
description = 'Provisioning test from the Windows Azure Python SDK'

storage_account_name = re.sub('\W', '', service_name)
storage_account_name = storage_account_name.replace('_', '')
storage_account_name = storage_account_name[:24]

# Create an affinity group for all the services related to this project
log.info("Checking availability of affinity group: '%s'", affinity_group)
if affinity_group not in [ag.name for ag in sms.list_affinity_groups()]:
    try:
        log.info("Creating new affinity_group: '%s'", affinity_group)
        sms.create_affinity_group(affinity_group, service_label, location,
            description)
    except WindowsAzureConflictError:
        log.error("Affinity Group '%s' has already been provisioned")
        sys.exit(1)

# Provision de hosted service itself if not already existing
log.info("Checking availability of hosted service: '%s'", service_name)
if service_name not in [s.service_name for s in sms.list_hosted_services()]:
    try:
        log.info("Creating new hosted service: '%s'", service_name)
        sms.create_hosted_service(service_name, service_label, description,
            affinity_group=affinity_group)
    except WindowsAzureConflictError:
        log.error("Hosted service '%s' has already been provisioned"
                  " by another user.", service_name)
        sys.exit(1)

cloud_service = sms.get_hosted_service_properties(service_name)
log.info("Using hosted service '%s' at: %s", service_name, cloud_service.url)

# Create the OS image

# Create a storage account if none is found for the given service

log.info("Checking availability of storage account: '%s'", storage_account_name)
storage_accounts = [sa.service_name for sa in sms.list_storage_accounts()]
if storage_account_name not in storage_accounts:
    try:
        log.info("Creating new storage account: '%s'", storage_account_name)
        sms.create_storage_account(storage_account_name,
            "Blob store for " + service_name, service_label,
            affinity_group=affinity_group)
    except WindowsAzureConflictError:
        log.error("Storage Account '%s' has already been provisioned"
                  " by another user.", storage_account_name)
        sys.exit(1)


log.info("Fetching keys for storage account: '%s'", storage_account_name)
n_tries = 3
sleep_duration = 10
keys = None
for i in range(n_tries):
    try:
        keys = sms.get_storage_account_keys(storage_account_name)
        break
    except WindowsAzureMissingResourceError:
        log.info("Not found, retrying (%d/%d) in %ds...", i + 1, n_tries,
                 sleep_duration)
        time.sleep(sleep_duration)
if keys is None:
    log.error("Failed to fetch keys for storage account '%s'",
              storage_account_name)
    sys.exit(1)

blob_service = BlobService(account_name=storage_account_name,
                           account_key=keys.storage_service_keys.primary)
blob_service.create_container('vhds')
os_image_url = "http://{}.blob.core.windows.net/vhds/{}".format(
    storage_account_name, target_blob_name)

# XXX: change the password: read it from os.environ or generate a random one
# to be printed on stdout
linux_config = LinuxConfigurationSet('hostname', 'username', 'secretA1,!', True)
# linux_config.ssh = None

if image_name is None:
    # Select the last Ubuntu daily build
    image_name = [i.name for i in sms.list_os_images()
                          if 'Ubuntu_DAILY_BUILD' in i.name][-1]

log.info("Using OS image '%s' at: %s", image_name, os_image_url)
os_hd = OSVirtualHardDisk(image_name, os_image_url, disk_label=target_blob_name)

log.info("Provisioning virtual machine deployment %s", service_name)
sms.create_virtual_machine_deployment(
    service_name=service_name,
    deployment_name=service_name,
    deployment_slot='production',
    label=service_label,
    role_name=service_name,
    system_config=linux_config,
    os_virtual_hard_disk=os_hd,
    role_size=role_size)