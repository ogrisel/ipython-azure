#!/usr/bin/env python

import random
import re
import os
import sys
import logging
import time
import string

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


class NodeController(object):
    """Controller class to provision an IPython cluster."""

    def __init__(self, service_name=None, storage_account_name=None,
                 affinity_group=None, username=None,
                 location='West US', subscription_id=None,
                 certificate_path='~/azure.pem', image_name=None,
                 password=None):
        if username is None:
            username = os.getlogin()
        self.username = username
        if service_name is None:
            service_name = username + '-ipython'
        self.service_name = service_name

        if affinity_group is None:
            self.affinity_group = service_name
        else:
            self.affinity_group = affinity_group

        if storage_account_name is None:
            storage_account_name = re.sub('\W', '', service_name)
            storage_account_name = storage_account_name.replace('_', '')
            storage_account_name = storage_account_name[:24]
        self.storage_account_name = storage_account_name

        self.location = location
        self.image_name = image_name
        
        if subscription_id is None:
            subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
        self.subscription_id = subscription_id

        certificate_path = os.path.expanduser(certificate_path)
        if not os.path.exists(certificate_path):
            raise IOError('Could not find certificate at ' + certificate_path)

        if password is None:
            symbols = string.letters + string.digits
            password = ''.join(random.sample(symbols, 10))
            password += ''.join(random.sample('-_+=,./#$', 2))
        self.password = password

        self.sms = ServiceManagementService(subscription_id, certificate_path)
        self.provisioning_requests = []

    def provision_node(self, role_size='Small'):
        """Provision a new node for the cluster"""
        # Provision an hosted service
        target_blob_name = self.service_name + ".vhd"
        service_label = self.service_name
        description = 'IPython Cluster provisioned by ' + self.username

        # Create an affinity group for all the services related to this project
        log.info("Checking availability of affinity group: '%s'",
                 self.affinity_group)

        group_names = [ag.name for ag in self.sms.list_affinity_groups()]
        if self.affinity_group not in group_names:
            try:
                log.info("Creating new affinity_group: '%s'",
                    self.affinity_group)
                self.sms.create_affinity_group(self.affinity_group,
                    service_label, location, description)
            except WindowsAzureConflictError:
                raise RuntimeError(
                    "Affinity Group '%s' has already been provisioned" %
                    self.affinity_group)

        # Provision de hosted service itself if not already existing
        log.info("Checking availability of hosted service: '%s'",
                 self.service_name)
        service_names = [s.service_name
                         for s in self.sms.list_hosted_services()]
        if self.service_name not in service_names:
            try:
                log.info("Creating new hosted service: '%s'", self.service_name)
                self.sms.create_hosted_service(self.service_name,
                    service_label, description,
                    affinity_group=self.affinity_group)
            except WindowsAzureConflictError:
                raise RuntimeError(
                    "Hosted service '%s' has already been provisioned"
                    " by another user." % self.service_name)

        cloud_service = self.sms.get_hosted_service_properties(
            self.service_name)
        log.info("Using hosted service '%s' at: %s",
                 self.service_name, cloud_service.url)

        # Create a storage account if none is found for the given service

        log.info("Checking availability of storage account: '%s'",
                 self.storage_account_name)
        storage_accounts = [sa.service_name
                            for sa in self.sms.list_storage_accounts()]
        if self.storage_account_name not in storage_accounts:
            try:
                log.info("Creating new storage account: '%s'",
                         self.storage_account_name)
                self.sms.create_storage_account(self.storage_account_name,
                    "Blob store for " + self.service_name, service_label,
                    affinity_group=self.affinity_group)
            except WindowsAzureConflictError:
                raise RuntimeError(
                    "Storage Account '%s' has already been provisioned"
                    " by another user." % self.storage_account_name)

        log.info("Fetching keys for storage account: '%s'",
            self.storage_account_name)
        n_tries = 3
        sleep_duration = 10
        keys = None
        for i in range(n_tries):
            try:
                keys = self.sms.get_storage_account_keys(
                    self.storage_account_name)
                break
            except WindowsAzureMissingResourceError:
                log.info("Not found, retrying (%d/%d) in %ds...", i + 1,
                    n_tries, sleep_duration)
                time.sleep(sleep_duration)
        if keys is None:
            raise RuntimeError("Failed to fetch keys for storage account '%s'"
                % self.storage_account_name)

        blob_service = BlobService(
            account_name=self.storage_account_name,
            account_key=keys.storage_service_keys.primary)
        blob_service.create_container('vhds')
        os_image_url = "http://{}.blob.core.windows.net/vhds/{}".format(
            self.storage_account_name, target_blob_name)

        linux_config = LinuxConfigurationSet('hostname', 'username',
            self.password, True)

        if self.image_name is None:
            # Select the last Ubuntu daily build
            self.image_name = [i.name for i in self.sms.list_os_images()
                               if 'Ubuntu_DAILY_BUILD' in i.name][-1]

        log.info("Using OS image '%s' at: %s", self.image_name, os_image_url)
        os_hd = OSVirtualHardDisk(self.image_name, os_image_url,
                                  disk_label=target_blob_name)

        log.info("Provisioning virtual machine deployment %s",
                 self.service_name)
        try:
            request = self.sms.create_virtual_machine_deployment(
                service_name=self.service_name,
                deployment_name=self.service_name,
                deployment_slot='production',
                label=service_label,
                role_name=self.service_name,
                system_config=linux_config,
                os_virtual_hard_disk=os_hd,
                role_size=role_size)
            self.provisioning_requests.append(request.request_id)
        except WindowsAzureConflictError:
            raise RuntimeError("Service '%s' has already been deployed" %
                               self.service_name)