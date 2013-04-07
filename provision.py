#!/usr/bin/env python

import os
import sys
import logging

from azure import WindowsAzureConflictError
from azure.servicemanagement import ServiceManagementService
from azure.servicemanagement import OSVirtualHardDisk
from azure.servicemanagement import LinuxConfigurationSet


FORMAT = '%(levelname)-8s %(asctime)-15s %(message)s'
logging.basicConfig(level=logging.INFO, format=FORMAT)

log = logging.getLogger()

subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
location = os.environ.get('AZURE_DEFAULT_LOCATION', 'West US')
role_size = os.environ.get('AZURE_DEFAULT_ROLE_SIZE', 'Small')

# Choose the latest ubuntu from sms.list_os_images()
image_name = ('b39f27a8b8c64d52b05eac6a62ebad85'
              '__Ubuntu-12_10-amd64-server-20130227-en-us-30GB')

certificate_path = os.path.expanduser('~/mycert.pem')

# Connect to the Azure platform and check that the location is valid
sms = ServiceManagementService(subscription_id, certificate_path)
assert location in [l.name for l in sms.list_locations()]

# Provision an hosted service
service_name = 'ipythonparalleldemo3'
affinity_group = service_name
service_label = 'ipython-parallel-demo'
description = 'IPython.parallel demo for Windows Azure'

# Create an affinity group for all the services related to this project
if affinity_group not in [ag.name for ag in sms.list_affinity_groups()]:
    try:
        log.info("Creating new affinity_group: '%s'", affinity_group)
        sms.create_affinity_group(affinity_group, service_label, location,
            description)
    except WindowsAzureConflictError:
        log.error("Affinity Group '%s' has already been provisioned")
        sys.exit(1)

# Provision de hosted service itself if not already existing
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

storage_accounts = [sa.service_name for sa in sms.list_storage_accounts()]
if service_name not in storage_accounts:
    try:
        log.info("Creating new storage account: '%s'", service_name)
        sms.create_storage_account(service_name,
            "Blob store for " + service_name, service_label,
            affinity_group=affinity_group)
    except WindowsAzureConflictError:
        log.error("Storage Account '%s' has already been provisioned"
                  " by another user.", service_name)
        sys.exit(1)

# os_hd = OSVirtualHardDisk(image_name, "http://ipythonparalleldemo.blob.core.windows.net/os_image")

# # XXX: change the password: read it from os.environ or generate a random one
# # to be printed on stdout
# linux_config = LinuxConfigurationSet('master', 'ipython', 'secretA1,!', True)


# sms.create_virtual_machine_deployment(
#     service_name=service_name,
#     deployment_name=service_name,
#     deployment_slot='production',
#     label=service_label,
#     role_name=service_name,
#     system_config=linux_config,
#     os_virtual_hard_disk=os_hd,
#     role_size=role_size)