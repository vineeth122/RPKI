#from msilib import sequence
import os
import sys
import json
import logging
from pathlib import Path
from typing import Sequence
#from unittest.util import _MAX_LENGTH
#import coloredlogs
import psutil
from asn1crypto.core import *
from asn1crypto.cms import ContentType, ContentInfo, EncapsulatedContentInfo
from mrtparse import *
from ipaddress import IPv4Address,IPv4Network,IPv6Address
from radix import *
import json

class ASID(Integer):
    pass


class AddrBits(BitString):
    pass

class Addr(Sequence):
    _fields=[
        ("address",AddrBits),
        ("maxlength",Integer,{"optional":True})
    ]

class AddrSet(SequenceOf):
    _child_spec = Addr



class AddrFamily(Sequence):
    _fields = [ ("addressFamily",OctetString),
                ("addresses",AddrSet)
            ]

class AddrSeq(SequenceOf):
    _child_spec= AddrFamily

class ROA(Sequence):
    _fields= [ ("version", Integer, {"implicit":0,"default":0}),
            ("asID", ASID),
            ("ipAddrBlocks", AddrSeq)
            ]

def ipv4_from_bits(xs):
    address = 0
    #print(len(xs))
    for x in xs:
        address= (address << 1) | x
    if len(xs) < 32:
        address <<= 32-len(xs)
    prefix_length=len(xs)
    return IPv4Address(address),prefix_length


def ipv6_from_bits(xs):
    address = 0
    #print(len(xs))
    for x in xs:
        address= (address << 1) | x
    if len(xs) < 128:
        address <<= 128-len(xs)
    prefix_length=len(xs)
    return IPv6Address(address),prefix_length


ContentType._map["1.2.840.113549.1.9.16.1.24"] = "routeOriginAuthz"
#ContentType.map["1.2.840.11359.1.9.16.1.24"]= "routeOriginAuthz"
EncapsulatedContentInfo._oid_specs["routeOriginAuthz"] = ROA


def load_roa(p):
    addresses = list()
#    print("contentinfo",ContentInfo.load(p.read_bytes()).native,"\n")
    cms= ContentInfo.load(p.read_bytes()).native
    #print(cms["content"]["encap_content_info"]["content_type"])
    #print(cms["content"]["encap_content_info"]["content_type"] == "1.2.840.11359.1.9.16.1.24")
    if cms["content"]["encap_content_info"]["content_type"] == "routeOriginAuthz":
        #print("hello")
        roa = cms["content"]["encap_content_info"]["content"]
        #print('wfwe',roa)
        for block in roa["ipAddrBlocks"]:
            family=int.from_bytes(block["addressFamily"],byteorder="big")
            #print("family",family)
            if family == 1:
                for addr in block["addresses"]:
                    address,prefix_length = ipv4_from_bits(addr["address"])
                    prefix=f"{address}/{prefix_length}"
                    if addr["maxlength"] is None:
                        max_length = prefix_length
                    else:
                        max_length = addr["maxlength"]
                    addresses.append((prefix,max_length,roa["asID"]))

            elif family == 2:
                for addr in block["addresses"]:
                    address,prefix_length = ipv6_from_bits(addr["address"])
                    prefix=f"{address}/{prefix_length}"
                    if addr["maxlength"] is None:
                        max_length = prefix_length
                    else:
                        max_length = addr["maxlength"]
                    addresses.append((prefix,max_length,roa["asID"]))
                pass
            else:
                raise Exception("unknown address family")
    return addresses

total_messages=0
total_invalid=0
total_valid=0
total_unknown=0

def load_check_mrt(p):
    print("enterd function",p)
#    print(rpki_rtree.nodes())
    for entry in Reader(p):
        try:            
            global total_messages
            total_messages+=1
            tv_sec= list(entry.data["timestamp"].keys())[0]
            tv_usec= entry.data["microsecond_timestamp"]  
            peer_ip = entry.data["peer_ip"]
            peer_asn = int(entry.data["peer_as"])
            if 1 in entry.data["afi"]:                
                as_path_type=entry.data['bgp_message']['path_attributes'][1]['type'][2]
                as_path_seq_set=entry.data['bgp_message']['path_attributes'][1]["value"]                      
                origin_as=entry.data['bgp_message']['path_attributes'][1]["value"][0]["value"][-1]
                nlri=entry.data['bgp_message']['nlri']
            if 2 in entry.data["afi"]:
                for pathi in entry.data['bgp_message']['path_attributes']:
                    if pathi["type"].get(2):
                        if pathi["type"][2] == "AS_PATH":
                            as_path_type=pathi["type"][2]
                            as_path_seq_set=pathi["value"]                
                            origin_as=pathi["value"][0]["value"][-1]
                            nlri=entry.data['bgp_message']['nlri']
                            break                        
            if len(nlri) > 0:
                if as_path_type.lower() == "as_path":
                        if 2 in as_path_seq_set[0]['type'] and 1 in as_path_seq_set[-1]['type']:
                            as_sequence=as_path_seq_set[0]["value"]
                            as_set=as_path_seq_set[-1]["value"]
                            as_path=[{"type":"sequence","asns":list(map(int,as_sequence))},{"type":"set","asns":list(map(int,as_set))}]
                        else:
                            as_sequence=as_path_seq_set[0]["value"]            
                            as_path=[{"type":"sequence","asns":list(map(int,as_sequence))}]         
                    #if as_path_value_type.lower() == "as_sequence":
                        for add_list  in nlri:
                            nlri_prefix_length=add_list["prefix_length"]
                            nlri_prefix=add_list["prefix"]                                
                            prefix_cov=rpki_rtree.search_covering(nlri_prefix,nlri_prefix_length)                                                
                            if len(prefix_cov) > 0:
                                #print("entered coverage")
                                #print(prefix_cov)
                                for cov in prefix_cov:                        
                                    if (cov.data.get(int(origin_as)) is not None) and (cov.data.get(int(origin_as),-1) >= nlri_prefix_length):                    
                                        break
                                    else:
                                        global total_invalid
                                        total_invalid+=1
                                        #print(prefix_cov)                        
                                        print(json.dumps({"type":"invalid","tv_sec":tv_sec,"tv_usec":tv_usec,"peer_ip":peer_ip,"peer_asn":peer_asn, \
                                            "prefix":f"{nlri_prefix}/{nlri_prefix_length}","as_path":as_path}))
                                        # print("invalid")
                            else:
                                global total_unknown
                                total_unknown+=1
                                print(json.dumps({"type":"unknown","tv_sec":tv_sec,"tv_usec":tv_usec,"peer_ip":peer_ip,"peer_asn":peer_asn, \
                                            "prefix":f"{nlri_prefix}/{nlri_prefix_length}","as_path":as_path}))



                    #print(f"{roas.keys()}")
        except:
            #import traceback
            #traceback.print_exc()
            #print("\n exception \n",entry.data)
            pass
    # print(total_messages,total_invalid,total_unknown,total_valid)
    return


rpki_rtree=Radix()
global rpkil
rpkil=[]


def main():
    #rpki_root= "U:/cy_net_sec/rpki_cache/repository/rsync"
    rpki_root=sys.argv[1]
    mrt_root=sys.argv[2]
    
    roas=dict()
    logging.info(f"loading ROAs from {rpki_root}")
    for root,dirs,files in os.walk(rpki_root):
        for f in files:
            p=Path(root)/f
            if not p.name.endswith("roa"):
                continue
            try:
                
                addresses= load_roa(p)
                for address, max_length, asn in addresses:                    
                    if ((str(address) is not None) and (asn is not None)):                                      
                        if rpki_rtree.search_exact(address) is not None:
                            
                            
                            if rnode.data.get(asn) is not None:
                                if rnode.data[asn] < max_length:
                                    #print("\n before",rnode.data[asn],rnode.prefix)
                                    rnode.data[asn] = max_length
                                    #print("\n after",rnode.data[asn],rnode.prefix)
                            else:
                                rnode.data[asn]=max_length
                        else:
                            rnode=rpki_rtree.add(str(address))
                            rnode.data[asn]= max_length
                        
                    
            except Exception as e:
                
                continue
    #load_check_mrt(str(mrt_root))
    for root,dirs,files in os.walk(mrt_root):
        
        for f in files:
            mrtp=Path(root)/f
            if not mrtp.name.endswith(".bz2"):
                continue
            try:                
                load_check_mrt(str(mrtp))
            except:
                pass
    print(json.dumps({"total_messages":total_messages,"total_invalid":total_invalid,"total_unknown":total_unknown,"total_unsafe":"null"}))

    rss_mb=psutil.Process().memory_info().rss/1000000
    logging.info(f"max RSS:{rss_mb}")
    assert rss_mb < 256



if __name__ == '__main__':
    main() 
