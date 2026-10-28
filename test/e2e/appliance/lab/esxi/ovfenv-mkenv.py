import sys, json
from xml.sax.saxutils import quoteattr
props, ns_attr = json.loads(sys.argv[1]), sys.argv[2] == "ns"
p = "".join('<Property %s=%s %s=%s/>' % ("oe:key" if ns_attr else "key", quoteattr(k), "oe:value" if ns_attr else "value", quoteattr(v)) for k, v in props)
print('<?xml version="1.0" encoding="UTF-8"?><Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ve="http://www.vmware.com/schema/ovfenv" oe:id=""><PlatformSection><Kind>VMware ESXi</Kind><Version>8.0.1</Version><Vendor>VMware, Inc.</Vendor><Locale>US</Locale></PlatformSection><PropertySection>%s</PropertySection></Environment>' % p)
