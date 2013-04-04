#!/usr/bin/env python

import os
import sys
import logging

from azure import WindowsAzureConflictError
from azure.servicemanagement import ServiceManagementService

FORMAT = '%(levelname)-8s %(asctime)-15s %(message)s'
logging.basicConfig(level=logging.INFO, format=FORMAT)

log = logging.getLogger()

subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
location = os.environ.get('AZURE_DEFAULT_LOCATION', 'West US')

certificate_path = os.path.expanduser('~/mycert.pem')

# Connect to the Azure platform and check that the location is valid
sms = ServiceManagementService(subscription_id, certificate_path)
assert location in [l.name for l in sms.list_locations()]

# Provision an hosted service
service_name = 'ipython-parallel-demo'
service_label = 'ipython-parallel-demo'
description = 'IPython.parallel demo for Windows Azure'

if service_name not in [s.service_name for s in sms.list_hosted_services()]:
    try:
        log.info("Creating new hosted service: '%s'", service_name)
        sms.create_hosted_service(service_name, service_label, description,
            location)
    except WindowsAzureConflictError:
        log.error("Hosted service '%s' has already been provisioned"
                  " by another user.", service_name)
        sys.exit(1)

cloud_service = sms.get_hosted_service_properties(service_name)
log.info("Using hosted service '%s' at: %s", service_name, cloud_service.url)