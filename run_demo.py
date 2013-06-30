import provision

p = provision.Provisioner('ipython-azure-demo')
p.launch_node(role_size='ExtraLarge')
print('Demo launched on: %s.cloudapp.net' % p.service_name)