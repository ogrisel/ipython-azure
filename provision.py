#!/usr/bin/env python

import random
import re
import os
import logging
import time
import string
import socket
import json
from contextlib import closing

from paramiko import RSAKey
from paramiko import SSHClient
from paramiko import AutoAddPolicy

from azure import WindowsAzureConflictError
from azure import WindowsAzureMissingResourceError
from azure.servicemanagement import ServiceManagementService
from azure.servicemanagement import OSVirtualHardDisk
from azure.servicemanagement import LinuxConfigurationSet
from azure.servicemanagement import ConfigurationSet
from azure.servicemanagement import ConfigurationSetInputEndpoint
from azure.storage import BlobService
from azure.servicemanagement import _XmlSerializer, _lower


DEFAULT_SALT_PROFILE = os.path.join(os.path.dirname(__file__), 'salt-profile')


DEFAULT_PORTS = (
    ('http', 'tcp', '80', '8888'),
    ('https', 'tcp', '443', '8443'),
    ('ssh', 'tcp', '22', '22'),
    ('salt-master-1', 'tcp', '4505', '4505'),
    ('salt-master-2', 'tcp', '4506', '4506'),
)

NOPASSWD_SCRIPT = """\
#!/usr/bin/env python

import os

sudoers_filename = '/etc/sudoers.d/waagent'
with open(sudoers_filename, 'rb') as f:
    sudoers = f.read()

with_passwd = "ALL = (ALL) ALL"
without_passwd = "ALL = (ALL) NOPASSWD: ALL"

if with_passwd in sudoers:
    new_sudoers = sudoers.replace(with_passwd, without_passwd)
    with open(sudoers_filename, 'w+') as f:
        f.write(new_sudoers)
    print('updated')
else:
    print('unchanged')
"""


FORMAT = '%(levelname)-8s %(asctime)-15s %(message)s'
logging.basicConfig(level=logging.INFO, format=FORMAT)

log = logging.getLogger()


#
# Install monkeypatch to workaround bug:
# https://github.com/WindowsAzure/azure-sdk-for-python/pull/83
#

@staticmethod
def network_configuration_to_xml(configuration):
    xml = _XmlSerializer.data_to_xml([(
        'ConfigurationSetType', configuration.configuration_set_type)])
    xml += '<InputEndpoints>'
    for endpoint in configuration.input_endpoints:
        xml += '<InputEndpoint>'
        xml += _XmlSerializer.data_to_xml(
            [('LoadBalancedEndpointSetName',
              endpoint.load_balanced_endpoint_set_name),
             ('LocalPort', endpoint.local_port),
             ('Name', endpoint.name),
             ('Port', endpoint.port)])

        if (endpoint.load_balancer_probe.path
                or endpoint.load_balancer_probe.port
                or endpoint.load_balancer_probe.protocol):
            xml += '<LoadBalancerProbe>'
            xml += _XmlSerializer.data_to_xml(
                [('Path', endpoint.load_balancer_probe.path),
                 ('Port',
                  endpoint.load_balancer_probe.port),
                 ('Protocol', endpoint.load_balancer_probe.protocol)])
            xml += '</LoadBalancerProbe>'

        xml += _XmlSerializer.data_to_xml([
            ('Protocol', endpoint.protocol),
            ('EnableDirectServerReturn',
             endpoint.enable_direct_server_return, _lower),
        ])
        xml += '</InputEndpoint>'
    xml += '</InputEndpoints>'
    xml += '<SubnetNames>'
    for name in configuration.subnet_names:
        xml += _XmlSerializer.data_to_xml([('SubnetName', name)])
    xml += '</SubnetNames>'
    return xml

_XmlSerializer.network_configuration_to_xml = network_configuration_to_xml


class NodeController(object):
    """Class to remotely control a VM instance with ssh"""

    def __init__(self, hostname, username, password=None,
                 key_filename=None, n_tries=1, sleep_duration=30,
                 timeout=60):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_filename = key_filename

        self.n_tries = n_tries
        self.sleep_duration = sleep_duration
        self.timeout = timeout
        self.ssh = None
        self.sftp = None

    def exec_command(self, cmd, use_pty=True, timeout=None,
                     payload_stdin=None, bufsize=-1):
        log.info("Executing '%s' on '%s':", cmd, self.hostname)
        self.check_connect()

        with closing(self.ssh.get_transport().open_session()) as chan:
            if timeout is not None:
                chan.settimeout(timeout)
            if use_pty:
                chan.get_pty()
            chan.exec_command(cmd)
            stdin = chan.makefile('wb', bufsize)
            stdout = chan.makefile('rb', bufsize)
            stderr = chan.makefile_stderr('rb', bufsize)
            try:

                if payload_stdin is not None:
                    stdin.write(payload_stdin)
                    stdin.flush()
                for line in stdout:
                    log.info("%s> %s", self.hostname, line.strip())
                for line in stderr:
                    log.warning("%s> %s", self.hostname, line.strip())
            except socket.timeout:
                self.disconnect()
                raise RuntimeError("Timeout while executing command: %s"
                                   % cmd)

    def install_ssh_keys(self, pubkey, privkey):
        """Install ssh keys on a newly provisioned node"""
        log.info("Installing ssh keys on %s", self.hostname)
        self.check_connect()

        ssh_folder = "/home/{}/.ssh".format(self.username)
        sftp = self.sftp
        try:
            sftp.mkdir(ssh_folder)
        except IOError:
            # folder already exists
            pass

        # Upload the cluster keys on the node
        sftp.put(pubkey, ssh_folder + '/id_rsa.pub')
        sftp.put(privkey, ssh_folder + '/id_rsa')

        # Add the public key to the authorized keys for later reconnection
        # without password.
        with sftp.open(ssh_folder + '/authorized_keys', 'w') as f:
            f.write(open(pubkey, 'rb').read())
            f.write('\n')

            # Optionally deploy the local public key of the current user
            id_rsa_pub = os.path.expanduser('~/.ssh/id_rsa.pub')
            if os.path.exists(id_rsa_pub):
                f.write(open(id_rsa_pub, 'rb').read())
                f.write('\n')

    def setup_sudo_nopasswd(self):
        """Remove the password requirements for sudoing

        For long running clusters, we don't store the password locally, hence
        we might want to trust the ssh auth for sudo operations.

        """
        log.info("Disabling password check for sudo")
        self.check_connect()

        script_file = "/home/{}/nopasswd.py".format(self.username)
        with self.sftp.open(script_file, 'w+') as f:
            f.write(NOPASSWD_SCRIPT)

        # Note: any sudo command needs a pseudo TTY interface on recent linux
        # boxes
        cmd = "sudo python " + script_file
        self.exec_command(cmd, payload_stdin=self.password + '\n')

    def bootstrap_salt(self, master_ip_address=None):
        log.info("Boostrapping salt on '%s'", self.hostname)

        cmd = "sudo /bin/sh -c 'echo \"{} salt\" >> /etc/hosts'"
        if master_ip_address is None:
            # This node is the master
            # Add localhost as salt master in local dns
            self.exec_command(cmd.format('127.0.0.1'))
        else:
            self.exec_command(cmd.format(master_ip_address))

        # Install and run both master and local minion on host
        cmd = "wget -q -O bootstrap-salt.sh http://bootstrap.saltstack.org"
        self.exec_command(cmd, timeout=300)

        if master_ip_address is None:
            # This node is the master
            self.exec_command("sudo sh bootstrap-salt.sh -M", timeout=300)
            # Accept the key from the local minion and confirm
            # TODO: use key pre-seeding instead
            node_name = self.hostname.split('.', 1)[0]
            self.exec_command("sudo salt-key -a " + node_name,
                              payload_stdin="y\n")
            # Check that salt is running as expected and the local minion is
            # connected
            self.exec_command("sudo salt '*' cmd.run 'uname -a'")
        else:
            # Just bootstrap the minion daemon
            self.exec_command("sudo sh bootstrap-salt.sh", timeout=300)

    def upload_salt_profile(self, salt_profile):
        for folder in os.listdir(salt_profile):
            folder_path = os.path.join(salt_profile, folder)
            if os.path.isdir(folder_path):
                log.info("Uploading configuration from: %s", folder_path)
                self.upload_folder(folder_path, '/srv/' + folder, delete=True)

    @staticmethod
    def quote(path):
        return "'{}'".format(path.replace("'", "\\'"))

    def upload_folder(self, local_path, remote_path, delete=False):
        self.check_connect()
        quoted_remote_path = self.quote(remote_path)
        if delete:
            self.exec_command("sudo rm -rf " + quoted_remote_path)
            self.exec_command("sudo mkdir -p " + quoted_remote_path)
            # Make sure that the sftp user has write access
            self.exec_command("sudo chown {} {}".format(
                self.username, quoted_remote_path))
        for child in os.listdir(local_path):
            local_child_path = os.path.join(local_path, child)
            remote_child_path = remote_path + '/' + child
            if os.path.isdir(local_child_path):
                try:
                    self.sftp.mkdir(remote_child_path)
                except IOError as e:
                    if delete:
                        raise e
                    # Otherwise assume the folder already exists
                # Recursive call
                self.upload_folder(local_child_path, remote_child_path)
            else:
                self.sftp.put(local_child_path, remote_child_path)

    def connect(self):
        self.ssh = self._make_ssh_client(self.n_tries, self.sleep_duration)
        self.sftp = self.ssh.open_sftp()

    def disconnect(self):
        if self.sftp is None:
            self.sftp.close()
        if self.ssh is None:
            self.ssh.close()

    def check_connect(self):
        if self.ssh is None or self.sftp is None:
            self.connect()

    def reconnect(self):
        self.disconnect()
        self.connect()

    def _make_ssh_client(self, n_tries, sleep_duration):
        c = SSHClient()
        c.set_missing_host_key_policy(AutoAddPolicy())
        for i in range(n_tries):
            try:
                c.connect(self.hostname, username=self.username,
                          password=self.password,
                          key_filename=self.key_filename,
                          timeout=self.timeout)
                return c
            except socket.error as e:
                log.info("Host '%s' not found, retrying (%d/%d) in %ds...",
                         self.hostname, i + 1, n_tries, sleep_duration)
                time.sleep(sleep_duration)
        raise e

    def __del__(self):
        self.disconnect()


class Provisioner(object):
    """Controller class to provision an IPython cluster."""

    def __init__(self, service_name=None, storage_account_name=None,
                 affinity_group=None, username='ipuser',
                 location='Central US', subscription_id=None,
                 certificate_path='~/.azure/managementCertificate.pem',
                 image_name=None, password=None, finger_print=None,
                 keys_folder='~/.azure/keys',
                 salt_profile=DEFAULT_SALT_PROFILE,
                 azure_config_file='~/.azure/config.json'):
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
            azure_config_file = os.path.expanduser(azure_config_file)
            with open(azure_config_file, 'rb') as f:
                subscription_id = json.load(f)['subscription']

        self.subscription_id = subscription_id

        certificate_path = os.path.expanduser(certificate_path)
        if not os.path.exists(certificate_path):
            raise IOError('Could not find certificate at ' + certificate_path)

        if password is None:
            symbols = string.letters + string.digits
            password = ''.join(random.sample(symbols, 10))
            password += ''.join(random.sample('-_+=,./#$', 2))
        self.password = password

        self.keys_folder = os.path.expanduser(keys_folder)

        self.sms = ServiceManagementService(subscription_id, certificate_path)
        self.provisioning_requests = []
        self.salt_profile = salt_profile

    def launch_node(self, role_size='Small', ports_config=DEFAULT_PORTS,
                    async=False):
        """Launch a new instance for the service"""
        log.info('Provisioning node with subscription_id="%s"',
                 self.subscription_id)
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
                                               service_label, self.location,
                                               description)
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
                log.info(
                    "Creating new hosted service: '%s'", self.service_name)
                self.sms.create_hosted_service(
                    self.service_name, service_label, description,
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
                self.sms.create_storage_account(
                    self.storage_account_name, "Blob store for " +
                    self.service_name, service_label,
                    affinity_group=self.affinity_group)
            except WindowsAzureConflictError:
                raise RuntimeError(
                    "Storage Account '%s' has already been provisioned"
                    " by another user." % self.storage_account_name)

        log.info("Fetching keys for storage account: '%s'",
                 self.storage_account_name)
        n_tries = 50
        sleep_duration = 30
        keys = None
        for i in range(n_tries):
            try:
                keys = self.sms.get_storage_account_keys(
                    self.storage_account_name)
                break
            except WindowsAzureMissingResourceError:
                log.info("Not found, retrying (%d/%d) in %ds...", i + 1,
                         n_tries, sleep_duration)
            except socket.gaierror as e:
                log.error("Error: %s, retrying (%d/%d) in %ds...", e, i + 1,
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

        linux_config = LinuxConfigurationSet(self.service_name, self.username,
                                             self.password, False)

        network_config = ConfigurationSet()
        network_config.configuration_set_type = 'NetworkConfiguration'
        for port_rule in ports_config:
            network_config.input_endpoints.input_endpoints.append(
                ConfigurationSetInputEndpoint(*port_rule))

        if self.image_name is None:
            # Select the last Ubuntu daily build
            self.image_name = [i.name for i in self.sms.list_os_images()
                               if 'Ubuntu-13_04' in i.name][-1]

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
                network_config=network_config,
                os_virtual_hard_disk=os_hd,
                role_size=role_size)
            self.provisioning_requests.append(request.request_id)
        except WindowsAzureConflictError:
            raise RuntimeError("Service '%s' has already been deployed" %
                               self.service_name)
        if not async:
            self._wait_for_async(request.request_id, self.service_name,
                                 success_callback=self.deploy_master_node)

    def destroy_node(self, destroy_vm=True, destroy_disk=True,
                     destroy_storage_account=True):
        """Destroy any running instance and related provisioned resources"""
        # TODO
        raise NotImplementedError()

    def get_ssh_keyfiles(self):
        """Generate a dedicated keypair for service or reuse previous"""
        if not os.path.exists(self.keys_folder):
            os.makedirs(self.keys_folder)

        privkey_filename = os.path.join(self.keys_folder,
                                        self.service_name + '_rsa')
        pubkey_filename = privkey_filename + '.pub'
        if (not os.path.exists(privkey_filename)
                or not os.path.exists(pubkey_filename)):
            # Generate a passwordless keypair
            k = RSAKey.generate(2048)
            k.write_private_key_file(privkey_filename)
            with open(pubkey_filename, 'wb') as f:
                f.write("{} {}".format(k.get_name(), k.get_base64()))
        return pubkey_filename, privkey_filename

    def get_master_controller(self):
        hostname = "{}.cloudapp.net".format(self.service_name)
        _, priv_key = self.get_ssh_keyfiles()
        return NodeController(
            hostname, self.username, password=self.password,
            key_filename=priv_key, n_tries=30, sleep_duration=30)

    def deploy_master_node(self, home_folder='home_folder'):
        """Use ssh to install master node with saltstack"""
        hostname = "{}.cloudapp.net".format(self.service_name)
        log.info("Configuring provisioned host '%s'", hostname)

        ctl = self.get_master_controller()
        ctl.setup_sudo_nopasswd()
        ctl.upload_salt_profile(self.salt_profile)
        ctl.bootstrap_salt()

        log.info("Uploading files from: %s", home_folder)
        ctl.upload_folder(home_folder, '/home/' + self.username)

        # Keys are put the home folder after the salt config has been
        # generated to be able to benefit from a home folder shared via NFS
        # in the salt state configuration for instance.
        ctl.install_ssh_keys(*self.get_ssh_keyfiles())

        # Install everything from the provided profile
        ctl.exec_command("sudo salt '*' state.highstate", timeout=1200)

    def refresh_salt(self, salt_profile=None):
        if salt_profile is None:
            salt_profile = self.salt_profile
        log.info("Reuploading updated salt profile '%s'", salt_profile)
        ctl = self.get_master_controller()
        ctl.upload_salt_profile(self.salt_profile)
        ctl.exec_command("sudo salt '*' state.highstate", timeout=1200)

    def _wait_for_async(self, request_id, service_name, success_callback=None,
                        expected=('Succeeded',), n_tries=10,
                        sleep_duration=30):
        for i in range(n_tries):
            try:
                result = self.sms.get_operation_status(request_id)
                if result.status != 'InProgress':
                    break
            except socket.error as e:
                log.warn("Ingnored socket error: %s", e)

            log.info("Waiting for request on '%s',"
                     " retrying (%d/%d) in %ds...",
                     service_name, i + 1, n_tries, sleep_duration)
            time.sleep(sleep_duration)

        if result.status not in expected:
            msg = 'Unexpected operation status: ' + result.status
            if getattr(result, 'error', None) is not None:
                msg += ', code: {}, message: {}'.format(
                    result.error.code, result.error.message)
            raise RuntimeError(msg)
        if success_callback is not None:
            success_callback()
