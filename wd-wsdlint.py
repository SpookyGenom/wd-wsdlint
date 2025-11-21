import argparse
import json

from lxml import etree
from collections import defaultdict

WSDL_NS = "http://schemas.xmlsoap.org/wsdl/"
XSD_NS = "http://www.w3.org/2001/XMLSchema"
WSP_NS = "http://schemas.xmlsoap.org/ws/2004/09/policy"
WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
SP_NS = "http://docs.oasis-open.org/wss-wssecurity-policy/200702"

SOAPBIND_NS = "http://schemas.xmlsoap.org/wsdl/soap/"
HTTPBIND_NS = "http://schemas.xmlsoap.org/wsdl/http/"
MIMEBIND_NS = "http://schemas.xmlsoap.org/wsdl/mime/"

SOAP12_NS = "http://schemas.xmlsoap.org/wsdl/soap12/"

NSMAP = {
    'wsdl': WSDL_NS,
    'soap12': SOAP12_NS,
    'soapbind': SOAPBIND_NS,
    'http': HTTPBIND_NS,
    'mime': MIMEBIND_NS,
    'xsd': XSD_NS,
    'wsp': WSP_NS,
    'wsu': WSU_NS,
    'sp': SP_NS
}

def parse_wsdl(wsdl_path):
    parser = etree.XMLParser(remove_blank_text=False, ns_clean=False, huge_tree=True)
    tree = etree.parse(wsdl_path, parser)
    root = tree.getroot()
    return tree, root

def load_config(config_path, service_name):
    with open(config_path, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    if service_name not in cfg['wss']:
        raise ValueError(f"Service '{service_name}' not found in config.")
    return cfg['wss'][service_name]

def find_service(root, service_name):
    for svc in root.findall('wsdl:service', namespaces=NSMAP):
        if svc.get('name') == service_name:
            return svc
    raise ValueError(f"wsdl:service '{service_name}' not found.")

def binding_for_port(root, port):
    binding_qname = port.get('binding')  # e.g., tns:Human_Resources_Binding
    return resolve_qname(root, binding_qname, tag='wsdl:binding')

def resolve_qname(root, qname_str, tag=None):
    # qname_str like 'tns:Foo'. Find element with matching name in given tag collection.
    prefix, local = qname_str.split(':', 1)
    ns = root.nsmap.get(prefix)
    if tag:
        for el in root.findall(tag, namespaces=NSMAP):
            if el.get('name') == local:
                return el
        return None
    return etree.QName(ns, local)

def porttype_for_binding(root, binding):
    type_qname = binding.get('type')  # e.g., tns:Human_ResourcesPortType
    return resolve_qname(root, type_qname, tag='wsdl:portType')

def prune_porttype_operations(porttype, keep_ops):
    for op in list(porttype.findall('wsdl:operation', namespaces=NSMAP)):
        if op.get('name') not in keep_ops:
            op.getparent().remove(op)

def collect_messages_from_porttype(porttype):
    msgs = set()
    for op in porttype.findall('wsdl:operation', namespaces=NSMAP):
        for child_name in ('input', 'output'):
            child = op.find(f'wsdl:{child_name}', namespaces=NSMAP)
            if child is not None and child.get('message'):
                msgs.add(child.get('message'))
        for child in op.findall('wsdl:fault', namespaces=NSMAP):
            if child.get('message'):
                msgs.add(child.get('message'))  
    return msgs

def find_messages(root, message_qnames):
    messages = []
    names = set(q.split(':',1)[1] for q in message_qnames)
    for msg in root.findall('wsdl:message', namespaces=NSMAP):
        if msg.get('name') in names:
            messages.append(msg)
    return messages

def prune_messages(root, keep_messages):
    keep_names = set(m.get('name') for m in keep_messages)
    for msg in list(root.findall('wsdl:message', namespaces=NSMAP)):
        if msg.get('name') not in keep_names:
            msg.getparent().remove(msg)

def collect_schema_qnames_from_messages(messages, root):
    qnames = set()
    for msg in messages:
        for part in msg.findall('wsdl:part', namespaces=NSMAP):
            for attr in ('element', 'type'):
                if part.get(attr):
                    qnames.add(resolve_qname(root, part.get(attr)))
    return qnames

def reachable_schema_items(root, seed_qnames):
    # Build graph: element -> type -> referenced types/elements. Keep within wsdl:types/xsd:schema
    schemas = root.findall('.//wsdl:types/xsd:schema', namespaces=NSMAP)
    by_name = defaultdict(list)
    for sch in schemas:
        tns = sch.get('targetNamespace')
        # Collect elements and types
        for el in sch.findall('xsd:element', namespaces=NSMAP):
            name = el.get('name')
            by_name[(tns, name)].append(el)
        for ct in sch.findall('xsd:complexType', namespaces=NSMAP):
            name = ct.get('name')
            by_name[(tns, name)].append(ct)
        for st in sch.findall('xsd:simpleType', namespaces=NSMAP):
            name = st.get('name')
            by_name[(tns, name)].append(st)
    # BFS over references
    keep = set()
    queue = list(seed_qnames)
    def add_refs(node):
        # Find type references via @type, @ref, xsd:extension/@base, etc.
        for attr in ('type', 'ref', 'base'):
            for el in node.xpath('.//@' + attr, namespaces=NSMAP):
                if ':' in el:
                    qn = resolve_qname(root, el)
                    queue.append(qn)
    while queue:
        qn = queue.pop()
        key = (qn.namespace, qn.localname)
        if key in keep:
            continue
        keep.add(key)
        for node in by_name.get(key, []):
            add_refs(node)
    return keep, schemas, by_name

def prune_schemas(keep_keys, schemas, by_name):
    # Remove elements/types not in 'keep'
    for sch in schemas:
        tns = sch.get('targetNamespace')
        for tag in ('xsd:element', 'xsd:complexType', 'xsd:simpleType'):
            for node in list(sch.findall(tag, namespaces=NSMAP)):
                name = node.get('name')
                if name is None:
                    continue
                key = (tns, name)
                if key not in keep_keys:
                    node.getparent().remove(node)
        # Optionally remove unused imports/includes; here we remove all to make monolithic
        for imp in list(sch.findall('xsd:import', namespaces=NSMAP)) + list(sch.findall('xsd:include', namespaces=NSMAP)):
            imp.getparent().remove(imp)

def prune_binding_operations(binding, keep_ops):
    for bop in list(binding.findall('wsdl:operation', namespaces=NSMAP)):
        if bop.get('name') not in keep_ops:
            bop.getparent().remove(bop)

def is_soap12_binding(binding):
    return binding.find('soapbind:binding', namespaces=NSMAP) is not None

def attach_policy_to_binding(binding, policy_tree):
    if binding.find('wsp:UsingPolicy', namespaces=NSMAP) is not None:
        binding.remove(binding.find('wsp:UsingPolicy', namespaces=NSMAP))
    binding.insert(1, policy_tree.getroot().findall('wsp:UsingPolicy', namespaces=NSMAP)[0])

    if binding.find('wsp:Policy', namespaces=NSMAP) is not None:
        binding.remove(binding.find('wsp:Policy', namespaces=NSMAP))
    binding.insert(2, policy_tree.getroot().findall('wsp:Policy', namespaces=NSMAP)[0])

def prune_bindings(root, target_binding, keep_ops, policy_tree=None):
    # Keep only the target binding; prune its operations and attach policy if SOAP 1.2
    for b in list(root.findall('wsdl:binding', namespaces=NSMAP)):
        if b is target_binding:
            prune_binding_operations(b, keep_ops)
            if is_soap12_binding(b) and policy_tree is not None:
                prune_existing_policy(root)
                attach_policy_to_binding(b, policy_tree)
        else:
            b.getparent().remove(b)

def prune_existing_policy(root):
    # Remove existing policy, if any, to attach the one provided in config file
    for n in list(root.findall('wsp:Policy', namespaces=NSMAP)):
        n.getparent().remove(n)

    for n in list(root.findall('wsp:UsingPolicy', namespaces=NSMAP)):
        n.getparent().remove(n)

def prune_service_ports(service, target_binding):
    # Keep only ports that reference the target binding
    target_name = target_binding.get('name')
    for port in list(service.findall('wsdl:port', namespaces=NSMAP)):
        bq = port.get('binding')
        if not bq or bq.split(':',1)[1] != target_name:
            port.getparent().remove(port)

def prune_unused_porttypes(root, target_porttype):
    for pt in list(root.findall('wsdl:portType', namespaces=NSMAP)):
        if pt is not target_porttype:
            pt.getparent().remove(pt)

def prune_unreferenced_messages(root, keep_messages):
    # Already pruned; this function ensures nothing else remains
    prune_messages(root, keep_messages)

def clean_unused_namespaces(root):
    # Minimal cleanup: lxml will keep nsmap; we avoid aggressive cleanup to preserve prefixes
    pass

def build_policy_tree(policy_path):
    parser = etree.XMLParser(dtd_validation=False,remove_blank_text=False, ns_clean=False)
    return etree.parse(policy_path, parser)

def write_wsdl(tree, output_path):
    tree.write(output_path, encoding='utf-8', xml_declaration=True, pretty_print=True)

def prune_wsdl(wsdl_path, config_path, service_name, output_path):
    tree, root = parse_wsdl(wsdl_path)
    cfg = load_config(config_path, service_name)
    keep_ops = set(cfg['keep_operations'])
    policy_tree = None
    if 'policy_file' in cfg and cfg['policy_file']:
        policy_tree = build_policy_tree(cfg['policy_file'])

    service = find_service(root, service_name)
    # Use the first port's binding as target
    ports = service.findall('wsdl:port', namespaces=NSMAP)
    if not ports:
        raise ValueError("No wsdl:port found in service.")
    target_binding = binding_for_port(root, ports[0])
    if target_binding is None:
        raise ValueError("Binding not found for the service port.")
    target_porttype = porttype_for_binding(root, target_binding)
    if target_porttype is None:
        raise ValueError("PortType not found for binding.")

    # 1) Prune portType operations
    prune_porttype_operations(target_porttype, keep_ops)

    # 2) Collect and prune messages
    message_qnames = collect_messages_from_porttype(target_porttype)
    keep_messages = find_messages(root, message_qnames)
    prune_unreferenced_messages(root, keep_messages)

    # 3) Collect schema dependencies and prune schemas
    seed_qnames = collect_schema_qnames_from_messages(keep_messages, root)
    keep_keys, schemas, by_name = reachable_schema_items(root, seed_qnames)
    prune_schemas(keep_keys, schemas, by_name)

    # 4) Prune bindings and attach policy
    prune_bindings(root, target_binding, keep_ops, policy_tree)

    # 5) Prune service ports and other portTypes
    prune_service_ports(service, target_binding)
    prune_unused_porttypes(root, target_porttype)

    # 6) Optionally clean namespaces (noop to preserve prefixes)
    clean_unused_namespaces(root)

    write_wsdl(tree, output_path)

def main():
    parser = argparse.ArgumentParser(description="Prune WSDL to keep only specified operations.")
    parser.add_argument('--wsdl', help="Path to the input WSDL file.")
    parser.add_argument('--config', help="Path to the JSON config file.")
    parser.add_argument('--service', help="Name of the wsdl:service to process.")
    parser.add_argument('--output', help="Path to the output pruned WSDL file.")
    args = parser.parse_args()

    prune_wsdl(args.wsdl, args.config, args.service, args.output)

if __name__ == "__main__":
    main()