#  OpenFlow rule set


from __future__ import print_function
import element, setting


"""generate exact and wildcard matching rules based on dst IP
""" 
class Ruleset:
    def __init__(self):
        # rule對應到哪個規則 dstip '12.103.125.156': (32, '12.103.125.156')
        self.rules = {}
        # ruleset : 有哪些規則 (mask, dstip) -> (8, '78.0.0.0'), (9, '12.128.0.0')
        self.ruleset = set()
        # dependent set
        self.depset = {}
        # dirdepset : 只擷取 depset 的直接dependent關係
        self.dirdepset = {}

    def get_depset(self, maxdep):
        for ri in self.ruleset:
            self.depset[ri] = []
            if ri[0] == 32: continue
            ri_range = element.get_ip_range(ri[1], ri[0])
            for rj in self.ruleset:
                if rj[0] < ri[0] or rj == ri: continue
                rj_range = element.get_ip_range(rj[1], rj[0])
                if ri_range[1] < rj_range[0] or rj_range[1] < ri_range[0]:
                    continue
                else:
                    self.depset[ri].append(rj)
                    if len(self.depset[ri]) > maxdep:
                        break
        return

    def get_direct_depset(self):
        from copy import deepcopy
        self.dirdepset = deepcopy(self.depset)
        for rs in self.depset:
            if rs[0] == 24:
                for dep_rs in self.depset[rs]:
                    if dep_rs[0] == 28:
                        self.dirdepset[rs] = list( set(self.depset[rs]) - set(self.depset[dep_rs]))
                        
    # def get_direct_depset(self, maxdep):
    #     ruleset = sorted(self.ruleset, reverse=True)
    #     count = 0
    #     for r_child in ruleset:
    #         count += 1
    #         if r_child[0] == 24: continue
    #         r_child_range = element.get_ip_range(r_child[1], r_child[0])
    #         for r_parent in ruleset:
    #             if r_parent in self.depset:
    #                 if len(self.depset[r_parent]) > maxdep:
    #                     break
    #             else:
    #                 self.depset[r_parent] = []
    #             if r_child[0] < r_parent[0] or r_parent == r_child: continue
    #             r_parent_range = element.get_ip_range(r_parent[1], r_parent[0])
    #             if r_child_range[1] < r_parent_range[0] or r_parent_range[1] < r_child_range[0]:
    #                 continue
    #             else:
    #                 self.depset[r_parent].append(r_child)
    #                 break
    #         if count % 1000 == 0:
    #             print(count)
    #     return

    def generate_ruleset_from_traffic(self, traffic_pkl, mask=24, rate=0, maxdep=setting.INF):
        traffic = element.de_serialize(traffic_pkl)
        from random import random
        for pkt in traffic.pkts:
            if pkt.dstip in self.rules: continue
            dice = random()
            # rate : 會產生出此比例的wildcard rule
            if dice <= rate:
                dstprefix = element.int2ip(element.get_ip_range(pkt.dstip, mask)[0])
                self.rules[pkt.dstip] = (24, dstprefix)
                self.ruleset.add((24, dstprefix))
            else:
                self.rules[pkt.dstip] = (32, pkt.dstip)
                self.ruleset.add((32, pkt.dstip))
        
        self.get_depset(maxdep)

        return
    
    def generate_ruleset_from_traffic_diff_mask(self, traffic_pkl, mask=24, rate=0, mask_rate=1, maxdep=setting.INF):
        traffic = element.de_serialize(traffic_pkl)
        from random import random
        for pkt in traffic.pkts:
            if pkt.dstip in self.rules: continue
            dice = random()
            # rate : 會產生出此比例的wildcard rule
            if dice <= rate*mask_rate:
                dstprefix = element.int2ip(element.get_ip_range(pkt.dstip, mask)[0])
                self.rules[pkt.dstip] = (24, dstprefix)
                self.ruleset.add((24, dstprefix))
            elif dice <= rate:
                dstprefix = element.int2ip(element.get_ip_range(pkt.dstip, 28)[0])
                self.rules[pkt.dstip] = (28, dstprefix)
                self.ruleset.add((28, dstprefix))
            else:
                self.rules[pkt.dstip] = (32, pkt.dstip)
                self.ruleset.add((32, pkt.dstip))
                
        self.get_depset(maxdep)
        self.get_direct_depset(maxdep)

        return

    def generate_ruleset_from_classbench(self, classbench_rule, classbench_trace, 
                                         maxdep=setting.INF, minpri=0):
        with open(classbench_rule, 'r') as f:
            lines = f.readlines()
            lines = [l.rstrip('\n').split('\t') for l in lines]
            for l in lines:
                # l = ['@107.80.165.63/32', '79.96.231.174/32', '1024 : 65535', '53 : 53', '0x11/0xFF', '0x0000/0x0000', '']
                # l[1].split('/') =  ['79.96.231.174', '32']
                [dstip, priority_str] = l[1].split('/')
                
                priority = int(priority_str)
                # remove rules with very low priority
                if priority < minpri:
                    self.ruleset.add((32, dstip))
                else:   
                    self.ruleset.add((priority, dstip))

        with open(classbench_trace, 'r') as f:
            lines = f.readlines()
            lines = [l.rstrip('\n').split('\t') for l in lines]
            for l in lines:
                # l = ['1879048191', '208108956', '161', '0', '17', '0', '15']
                dstip_int = int(l[1])
                # dstip : l[1] 轉成 ipv4 208108956 -> 12.103.125.156
                dstip = element.int2ip(dstip_int)
                # all_dstprefix : 從0~32的mask跑一次 12.103.125.156 -> {0: '0.0.0.0" .... 31: '12.103.125.156', 32: '12.103.125.156'}
                all_dstprefix = {mask: element.int2ip(element.get_ip_range(dstip, mask)[0])
                                 for mask in range(33)}
                for mask in range(32, minpri-1, -1):
                    if (mask, all_dstprefix[mask]) in self.ruleset:
                        self.rules[dstip] = (mask, all_dstprefix[mask])
                        break

                # fail to match
                if dstip not in self.rules:
                    self.rules[dstip] = (32, dstip)
                    self.ruleset.add((32, dstip))

        self.get_depset(maxdep)
                
        return


if __name__ == '__main__':
    rs = Ruleset()
    rs.generate_ruleset_from_traffic('sample.pkl')

    print(rs.rules)
    print(rs.ruleset)
    print(rs.depset)

    rs = Ruleset()
    rs.generate_ruleset_from_classbench('test_rule', 'test_rule_trace', minpri=8)

    print(rs.rules)
    print(rs.ruleset)
    print(rs.depset)

