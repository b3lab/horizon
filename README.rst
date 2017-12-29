B3LAB - OpenStack Dashboard Register Panel
==========================================

Horizon is a Django-based project aimed at providing a complete OpenStack Dashboard along with an extensible framework for building new dashboards from reusable components. The openstack_dashboard module is a reference implementation of a Django site that uses the horizon app to provide web-based interactions with the various OpenStack projects.

Our forked project of Horizon at b3labregister/pike branch includes a self registration panel for OpenStack Pike version. This document describes how to install Horizon Dashboard with a registration panel for OpenStack Pike.

REQUIREMENTS
============

You need a running OpenStack (stable/pike) installation. You can use Devstack as you test environment.
Be aware b3labegister/pike branch is developed for OpenStack stable/pike version and it may not work with other versions.
It is highly recommended for you to try this installation in a virtual environment first.

INSTALLATION
============

Install required packages (Ubuntu)


.. sourcecode:: console  

  $ sudo apt-get install python-pip python-dev build-essential   
  $ sudo pip install --upgrade pip 
  
Install openstack_user_manager package, developed by B3LAB

.. sourcecode:: console  

  $ git clone https://github.com/b3lab/safir_openstack_user_manager.git  
  $ cd safir_openstack_user_manager/  
  $ sudo python setup.py install

Create or edit /etc/openstack/clouds.yaml and configure cloud-admin section with your cloud parameters.
$ sudo vi /etc/openstack/clouds.yaml
  
.. sourcecode:: console  

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

Install safir_email_notifier package, developed by B3LAB  

.. sourcecode:: console  

  $ git clone https://github.com/b3lab/safir_email_notifier.git  
  $ cd safir_email_notifier/  
  $ sudo python setup.py install

Install django-openstack-auth with b3lab register panel patch

.. sourcecode:: console  

  $ git clone https://github.com/b3lab/django_openstack_auth.git -b b3labregister/pike  
  $ cd django_openstack_auth  
  $ sudo python setup.py install
  
Install Horizon with b3lab register panel patch

.. sourcecode:: console  

  $ git clone https://github.com/b3lab/horizon.git -b b3labregister/pike  
  $ cd horizon  
  $ cp openstack_dashboard/local/local_settings.py.example openstack_dashboard/local/local_settings.py  
  $ vi openstack_dashboard/local/local_settings.py  
  
Edit local_settings.py with your settings according to [1] and configure the following settings for the register panel.
[1] https://docs.openstack.org/pike/install-guide-ubuntu/horizon-install.html

Set email host settings.  

.. sourcecode:: console  

  EMAIL_HOST = 'smtp.a.com'
  EMAIL_PORT = 25
  EMAIL_HOST_USER = 'a@a.com'
  EMAIL_HOST_PASSWORD = 'a'
  EMAIL_USE_TLS = True

Set initial private networks settings for new users.

.. sourcecode:: console 

  OPENSTACK_EXT_NET = 'public-network-name'
  OPENSTACK_DNS_NAMESERVERS = ['172.16.1.1']
  OPENSTACK_DEFAULT_SUBNET_CIDR = '10.0.0.0/24'
  OPENSTACK_DEFAULT_GATEWAY_IP = '10.0.0.1'

Set authentication token secrets.

.. sourcecode:: console  
  
  TOKEN_SECRET_KEY = 'secret'
  TOKEN_SECURITY_PASSWORD_SALT = 'secret'

Set OpenStack cloud config name.

.. sourcecode:: console  

  CLOUD_CONFIG_NAME = 'cloud-admin'

Set user agreement file path.

.. sourcecode:: console  

  USER_AGREEMENT_FILE = '/path/to/user/agreement/file'

Configure apache2 to use this dashboard and restart apache2 service.
