import provision
import sys

if len(sys.argv) > 1:
    service_name = sys.argv[1]
else:
    service_name = 'ipython-azure-demo'

p = provision.Provisioner(sys.argv[1])
p.launch_node(role_size='ExtraLarge')

print('Demo launched on: http://%s.cloudapp.net' % p.service_name)
