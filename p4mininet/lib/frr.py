# For BGP
# daemons = """
# zebra=yes
# bgpd=yes

# vtysh_enable=yes
# zebra_options="  -A 127.0.0.1 -s 90000000 -M dplane_fpm_nl"
# bgpd_options="   --daemon -A 127.0.0.1"
# """

# For OSPF
daemons = """
zebra=yes
ospfd=yes
ospf6d=yes

vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000 -M dplane_fpm_nl"
ospfd_options="  --daemon -A 127.0.0.1"
ospf6d_options=" --daemon -A ::1"
"""

vtysh = """
hostname {name}
no service integrated-vtysh-config
"""


# ospf_conf = """\
# enable
# configure terminal
# fpm address 127.0.0.1 port 2620
# !
# interface {p4rt_intf}
#   ip ospf passive
# !
# router ospf
#   router-info area 0.0.0.0
#   network 10.0.0.0/8 area 0.0.0.0
# !
# """


# no_ipv6_nd = """\
# enable
# configure terminal
# interface {}
# no ipv6 nd suppress-ra
# """