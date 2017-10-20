B3LAB - OpenStack Dashboard Register Panel
==========================================
  
Horizon is the canonical implementation of OpenStack’s Dashboard, which provides a web based user interface to OpenStack services. However basically it does not have a Self Registration Panel, which does not make sense that a cloud platform needs a human interaction for registration purposes.  
  
Our forked project of Horizon at b3lab/register branch includes a self registration panel. This document describes how to install Horizon Dashboard with a registration panel.  
  
REQUIREMENTS
============
  
You need a running OpenStack (stable/mitaka) installation. You can use Devstack as you test environment.  
Be aware B3LAB/Register panel developed over Horizon stable/mitaka version and it may not work with other versions.  
  
INSTALLATION
============
  
Install required packages (Ubuntu)  
  
$ sudo apt-get install python-pip python-dev build-essential   
$ sudo pip install --upgrade pip 
  
Install openstack_user_management package, developed by B3LAB  
  
Download package from https://pypi.python.org/pypi/openstack_user_management  
$ sudo pip install openstack_user_management-0.1.0.dev4.tar.gz  

Create or edit /etc/openstack/clouds.yaml and configure cloud-admin section with you cloud parameters.  
$ sudo vi /etc/openstack/clouds.yaml  
  
```
clouds:
   cloud-admin:
    auth:
      auth_url: http://<contoller_node_hostname>:5000/v3
      password: <admin_password>
      project_domain_name: default
      project_name: admin
      user_domain_name: default
      username: admin
    identity_api_version: '3'
    region_name: RegionOne
    volume_api_version: '2'
```
  
Install django-openstack-auth with b3lab/register patch  
  
$ git clone https://github.com/b3lab/django_openstack_auth.git -b b3labregister/mitaka  
$ cd django-openstack-auth  
$ sudo pip install .  
  
Install Horizon with b3lab/register patch  
  
$ git clone https://github.com/b3lab/horizon.git -b b3labregister/mitaka  
$ cd horizon  
$ cp openstack_dashboard/local/local_settings.py.example openstack_dashboard/local/local_settings.py  
$ vi openstack_dashboard/local/local_settings.py  
  
Edit local_settings.py with your settings according to [1].  
[1] http://docs.openstack.org/mitaka/install-guide-ubuntu/horizon-install.html#install-and-configure-components  
  
  Set email host settings.  
```
EMAIL_HOST = 'a@a.com'  
EMAIL_PORT = 25  
EMAIL_HOST_USER = 'a'  
EMAIL_HOST_PASSWORD = 'a'  
EMAIL_USE_TLS = True 
```   
  Set initial private networks settings for new users.  
```  
OPENSTACK_EXT_NET = 'ext-net'  
OPENSTACK_DNS_NAMESERVERS = ['172.16.1.1']  
OPENSTACK_DEFAULT_SUBNET_CIDR = '10.0.0.0/24'  
OPENSTACK_DEFAULT_GATEWAY_IP = '10.0.0.1'  
```  
  Set authentication token secrets.  
```  
TOKEN_SECRET_KEY = 'secret'  
TOKEN_SECURITY_PASSWORD_SALT = 'secret'  
```  
  
Configure apache2 to use this dashboard and restart apache2 service.  

  
