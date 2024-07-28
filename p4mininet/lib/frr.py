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

vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000 -M dplane_fpm_nl"
ospfd_options="  --daemon -A 127.0.0.1"
"""

vtysh = """
hostname {name}
no service integrated-vtysh-config
"""

bgp_conf = """\
enable
configure terminal
fpm address 127.0.0.1 port 2620
!
router bgp {as_number}
  bgp router-id {router_id}
  no bgp default ipv4-unicast
  no bgp ebgp-requires-policy
  neighbor CLOS peer-group
  neighbor CLOS remote-as external
  neighbor CLOS bfd
  neighbor CLOS capability extended-nexthop
  neighbor {l_name}_{s_name1} interface peer-group CLOS
  neighbor {l_name}_{s_name2} interface peer-group CLOS
  neighbor {l_name}_{s_name1} capability extended-nexthop
  neighbor {l_name}_{s_name2} capability extended-nexthop
  address-family ipv6 unicast
    redistribute connected
    neighbor CLOS activate
  exit-address-family
!
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