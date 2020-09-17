#  implement basic controller functions


from __future__ import print_function
import element
import setting
import predict


class Controller:
    def __init__(self, topo, soft_labels=None, ruleset_pkl=None):
        self.topo = topo
        self.switch_num = len(topo)
        self.soft_labels = soft_labels

        # shortest_pathes : 例如3個switch，就會產生{0: {}, 1: {}, 2: {}}
        self.shortest_pathes = {label: {} for label in range(self.switch_num)}
        # 取得每個switch間的shortest_pathes()
        self.get_shortest_pathes()
        self.parent_count = {label: {} for label in range(self.switch_num)}
        self.installed = {label: {} for label in range(self.switch_num)}
        #匯入ruleset
        if ruleset_pkl is not None:
            self.ruleset = element.de_serialize(ruleset_pkl)
        self.install_num = {}
        self.predictor = None

    def add_predictor(self, predictor_name):
        if predictor_name == setting.PREDICTOR_DEFAULT:
            self.predictor = predict.Predictor()
        elif predictor_name == setting.PREDICTOR_SIMPLE:
            self.predictor = predict.SimplePredictor()
        elif predictor_name == setting.PREDICTOR_Q:
            self.predictor = predict.QPredictor()
            self.predictor.init(self.switch_num)
        elif predictor_name == setting.PREDICTOR_DQN:
            self.predictor = predict.DQNPredictor()
            self.predictor.init(self.switch_num)
        else:
            raise NameError('Error. No such predictor. Exit')
        return

    def record_install(self, rule):
        if rule in self.install_num: 
            self.install_num[rule] += 1
        else:
            self.install_num[rule] = 1

    # 計算封包傳輸的時間
    def get_delay(self, path, size=1500):  # maximum Ethernet frame (1500B)
        delay = setting.LINK_RATE*size*(len(path)-1)
        for hop in path:
            if hop == setting.CTRL:
                delay += setting.CONTROLLER_DELAY
            elif self.soft_labels is not None and hop in self.soft_labels:
                delay += setting.SOFTWARE_FWD_DELAY
            else:
                delay += setting.HARDWARE_FWD_DELAY
        return delay

    def get_shortest_pathes(self, exclude_points=None):
        for src in range(self.switch_num):
            spathes = element.shortest_pathes(self.topo, src, exclude_points)
            for dst in range(self.switch_num):
                spathes[dst] = sorted([(self.get_delay(sp), sp) for sp in spathes[dst]])
                self.shortest_pathes[src][dst] = [sp for (delay, sp) in spathes[dst]]
        return

    def packet_in(self, label, pkt, reason, curtime, mode=setting.MODE_DEFAULT):
        if mode == setting.MODE_DEFAULT:  # install exact-match 5-tuple rules hop-by-hop
            return self.packet_in_default(label, pkt, curtime)
        elif mode == setting.MODE_SPATH:  # install exact-match 5-tuple rules on shortest-path
            return self.packet_in_spath(label, pkt, curtime)
        elif mode == setting.MODE_HARD:  # install hard timeout rules based on rule set hop-by-hop
            return self.packet_in_hard(label, pkt, curtime)
        elif mode == setting.MODE_IDLE:  # install idle timeout rules
            return self.packet_in_idle(label, pkt, curtime)
        elif mode == setting.MODE_HYBRID:  # install hybrid timeout rules
            return self.packet_in_hybrid(label, pkt, curtime)
        elif mode == setting.MODE_MINE:  # install mine timeout rules
            return self.packet_in_mine(label, pkt, reason, curtime)
        else:
            raise NameError('Error. No such packet-in mode. Exit.')

    def packet_in_default(self, label, pkt, curtime):  
        dst = pkt.dst
        path = self.shortest_pathes[label][dst][0]
        field = setting.FIELD_TP
        priority = 40
        match_field = pkt.tp
        action = [(setting.ACT_FWD, path[1])]
        entry = element.Entry(field, priority, match_field, action, 
                              flag=setting.FLAG_REMOVE_NOTIFY, 
                              ts=curtime, timeout=setting.DEFAULT_TIMEOUT, 
                              timeout_type=setting.TIMEOUT_IDLE)  # 1s idle timeout
        inst = [(setting.INST_ADD, label, entry)]  # instructions = [(action, object, content), ...]
        return inst

    def packet_in_spath(self, label, pkt, curtime):  
        dst = pkt.dst
        path = self.shortest_pathes[label][dst][0]
        instractions = []
        field = setting.FIELD_TP
        priority = 40
        match_field = pkt.tp
        for cnt in range(len(path)-1):
            action = [(setting.ACT_FWD, path[cnt+1])]
            entry = element.Entry(field, priority, match_field, action, 
                                  flag=setting.FLAG_REMOVE_NOTIFY, 
                                  ts=curtime, timeout=setting.DEFAULT_TIMEOUT, 
                                  timeout_type=setting.TIMEOUT_IDLE)  # 1s idle timeout
            inst = (setting.INST_ADD, path[cnt], entry)
            instractions.append(inst)
        return instractions
        
    def packet_in_idle(self, label, pkt, curtime):
        instractions = []
        dst = pkt.dst
        path = self.shortest_pathes[label][dst][0]
        field = setting.FIELD_DSTIP
        priority = 32
        match_field = pkt.dstip

        timeout = setting.DEFAULT_TIMEOUT
        if self.predictor.name == setting.PREDICTOR_SIMPLE:
            rule = (32, match_field)
            self.predictor.update((setting.INFO_PACKET_IN, label, curtime, rule))
            timeout = self.predictor.predict(rule, curtime, label)
        if (self.predictor.name == setting.PREDICTOR_Q or 
            self.predictor.name == setting.PREDICTOR_DQN):
            rule = (32, match_field)
            timeout = self.predictor.predict(rule, curtime, label)

        for cnt in range(len(path)-1):
            action = [(setting.ACT_FWD, path[cnt+1])]
            entry = element.Entry(field, priority, match_field, action, 
                                  flag=setting.FLAG_REMOVE_NOTIFY, 
                                  ts=curtime, timeout=timeout, 
                                  timeout_type=setting.TIMEOUT_IDLE)
            instractions.append((setting.INST_ADD, path[cnt], entry))
            self.record_install((32, match_field))
        return instractions

    def packet_in_hard(self, label, pkt, curtime):
        rule = self.ruleset.rules[pkt.dstip]
        deprules = self.ruleset.depset[rule]

        timeout = setting.DEFAULT_TIMEOUT
        if self.predictor.name == setting.PREDICTOR_SIMPLE:
            self.predictor.update((setting.INFO_PACKET_IN, label, curtime, rule))
            timeout = self.predictor.predict(rule, curtime, label)
        if (self.predictor.name == setting.PREDICTOR_Q or 
            self.predictor.name == setting.PREDICTOR_DQN):
            timeout = self.predictor.predict(rule, curtime, label)

        instractions = []
        dst = pkt.dst
        path = self.shortest_pathes[label][dst][0]    
        if rule[0] == 32:
            field = setting.FIELD_DSTIP
            priority = 32
        else:
            field = setting.FIELD_DSTPREFIX[rule[0]]
            priority = rule[0]
        match_field = rule[1]
        for cnt in range(len(path)-1):
            action = [(setting.ACT_FWD, path[cnt+1])]
            entry = element.Entry(field, priority, match_field, action, 
                                  flag=setting.FLAG_REMOVE_NOTIFY, ts=curtime, 
                                  timeout=timeout, timeout_type=setting.TIMEOUT_HARD)
            instractions.append((setting.INST_ADD, path[cnt], entry))
            self.record_install(rule)

        for r in deprules:
            if r[0] == 32:
                field = setting.FIELD_DSTIP # fwd to exact ip
                priority = 32
            else:
                field = setting.FIELD_DSTPREFIX[r[0]]
                priority = r[0]
            match_field = r[1]
            for cnt in range(len(path)-1):
                action = [(setting.ACT_FWD, path[cnt+1])]
                entry = element.Entry(field, priority, match_field, action, 
                                      flag=None, ts=curtime, 
                                      timeout=timeout, timeout_type=setting.TIMEOUT_HARD)
                instractions.append((setting.INST_ADD, path[cnt], entry))
                self.record_install(r)

        return instractions

    def packet_in_hybrid(self, label, pkt, curtime):
        rule = self.ruleset.rules[pkt.dstip]
        deprules = self.ruleset.depset[rule]

        timeout = setting.DEFAULT_TIMEOUT
        if self.predictor.name == setting.PREDICTOR_SIMPLE:
            self.predictor.update((setting.INFO_PACKET_IN, label, curtime, rule))
            timeout = self.predictor.predict(rule, curtime, label)
            # with open('data/itm_timeout', 'a') as f:
            #     print('{} {}'.format(rule,timeout), file=f)
        if (self.predictor.name == setting.PREDICTOR_Q or 
            self.predictor.name == setting.PREDICTOR_DQN):
            timeout = self.predictor.predict(rule, curtime, label)
            # with open('data/{}_timeout'.format(self.predictor.name), 'a') as f:
            #     print('{} {}'.format(rule,timeout), file=f)           

        instractions = []
        dst = pkt.dst
        path = self.shortest_pathes[label][dst][0]
        if rule[0] == 32:
            field = setting.FIELD_DSTIP
            priority = 32
        else:
            field = setting.FIELD_DSTPREFIX[rule[0]]
            priority = rule[0]
        match_field = rule[1]
        for cnt in range(len(path)-1):
            action = [(setting.ACT_FWD, path[cnt+1])]
            entry = element.Entry(field, priority, match_field, action, 
                                  flag=setting.FLAG_REMOVE_NOTIFY, ts=curtime, 
                                  timeout=timeout, timeout_type=setting.TIMEOUT_IDLE)
            instractions.append((setting.INST_ADD, path[cnt], entry))
            self.record_install(rule)

        for r in deprules:
            if r[0] == 32:
                field = setting.FIELD_DSTIP
                priority = 32
            else:
                field = setting.FIELD_DSTPREFIX[r[0]]
                priority = r[0]
            match_field = r[1]
            for cnt in range(len(path)-1):
                action = [(setting.ACT_FWD, path[cnt+1])]
                entry = element.Entry(field, priority, match_field, action, 
                                      flag=None, ts=curtime, 
                                      timeout=setting.INF, 
                                      timeout_type=setting.TIMEOUT_HARD)
                instractions.append((setting.INST_ADD, path[cnt], entry))
                if r in self.parent_count[path[cnt]]:
                    self.parent_count[path[cnt]][r] += 1
                else:
                    self.parent_count[path[cnt]][r] = 1
                self.record_install(r)
            
        return instractions

    def packet_in_mine(self, label, pkt, reason, curtime):
        rule = self.ruleset.rules[pkt.dstip]
        deprules = self.ruleset.depset[rule]
        dirdeprules = self.ruleset.dirdepset[rule]
        #dirdeprules = deprules
        timeout = setting.DEFAULT_TIMEOUT
        if self.predictor.name == setting.PREDICTOR_SIMPLE:
            self.predictor.update((setting.INFO_PACKET_IN, label, curtime, rule))
            timeout = self.predictor.predict(rule, curtime, label)
            # with open('data/itm_timeout', 'a') as f:
            #     print('{} {}'.format(rule,timeout), file=f)
        if (self.predictor.name == setting.PREDICTOR_Q or 
            self.predictor.name == setting.PREDICTOR_DQN):
            timeout = self.predictor.predict(rule, curtime, label)
            # with open('data/{}_timeout'.format(self.predictor.name), 'a') as f:
            #     print('{} {}'.format(rule,timeout), file=f)           

        instractions = []
        dst = pkt.dst
        path = self.shortest_pathes[label][dst][0]
        if rule[0] == 32:
            field = setting.FIELD_DSTIP
            priority = 32
        else:
            field = setting.FIELD_DSTPREFIX[rule[0]]
            priority = rule[0]
        match_field = rule[1]

        # 如果是no match就代表是新的封包，安裝timeout idle
        if reason == setting.OFPR_NO_MATCH:
            for cnt in range(len(path)-1):
                action = [(setting.ACT_FWD, path[cnt+1])]
                entry = element.Entry(field, priority, match_field, action, 
                                    flag=setting.FLAG_REMOVE_NOTIFY, ts=curtime, 
                                    timeout=timeout, timeout_type=setting.TIMEOUT_IDLE)
                instractions.append((setting.INST_ADD, path[cnt], entry))
                self.installed[path[cnt]][rule] = True
                self.record_install(rule)
        # 如果是action就代表有安裝過parent封包，就安裝timeout hard and set inf timeout
        elif reason == setting.OFPR_ACTION:
            for cnt in range(len(path)-1):
                action = [(setting.ACT_FWD, path[cnt+1])]
                entry = element.Entry(field, priority, match_field, action, 
                        flag=setting.FLAG_REMOVE_NOTIFY, ts=curtime, 
                        timeout=setting.INF, 
                        timeout_type=setting.TIMEOUT_HARD)
                instractions.append((setting.INST_ADD, path[cnt], entry))
                self.installed[path[cnt]][rule] = True
                self.record_install(rule)

        for r in dirdeprules:
            if r[0] == 32:
                field = setting.FIELD_DSTIP
                priority = 32
            elif r[0] == 28:
                field = setting.FIELD_DSTPREFIX[r[0]]
                priority = r[0]
            else:
                field = setting.FIELD_DSTPREFIX[r[0]]
                priority = r[0]
            match_field = r[1]
            # priority=28 則在ingress switch設為收到要packet in TODO 未來要改成判斷是否packet in
            if r[0] == 28:
                action = [(setting.ACT_FWD, setting.CTRL)]
                entry = element.Entry(field, priority, match_field, action, 
                                    flag=None, ts=curtime, 
                                    timeout=setting.INF, 
                                    timeout_type=setting.TIMEOUT_HARD)
                instractions.append((setting.INST_ADD, path[0], entry))
                if r in self.parent_count[path[0]]:
                    self.parent_count[path[0]][r] += 1
                else:
                    self.parent_count[path[0]][r] = 1
                self.record_install(r)
            else:    
                for cnt in range(len(path)-1):
                    action = [(setting.ACT_FWD, path[cnt+1])]
                    entry = element.Entry(field, priority, match_field, action, 
                                        flag=None, ts=curtime, 
                                        timeout=setting.INF, 
                                        timeout_type=setting.TIMEOUT_HARD)
                    instractions.append((setting.INST_ADD, path[cnt], entry))
                    if r in self.parent_count[path[cnt]]:
                        self.parent_count[path[cnt]][r] += 1
                    else:
                        self.parent_count[path[cnt]][r] = 1
                    self.record_install(r)
        return instractions

    def flow_removed(self, label, expire, overflow, curtime, mode=setting.MODE_DEFAULT):
        # update predictor
        if self.predictor.name == setting.PREDICTOR_SIMPLE:
            for entry in expire:
                rule = (entry.priority, entry.match_field)
                self.predictor.update((setting.INFO_FLOW_REMOVED, label, 
                                       curtime, rule))
        
        elif (self.predictor.name == setting.PREDICTOR_Q or 
              self.predictor.name == setting.PREDICTOR_DQN):
            for entry in expire+overflow:
                self.predictor.update((setting.INFO_FLOW_REMOVED, label,
                                       curtime, entry))

        # handle flow removed
        if mode in [setting.MODE_DEFAULT, setting.MODE_HARD, 
                    setting.MODE_IDLE, setting.MODE_SPATH]:
            return []
        elif mode == setting.MODE_HYBRID:
            return self.flow_removed_hybrid(label, expire, overflow, curtime)
        elif mode == setting.MODE_MINE:
            # TODO change hybrid into mine
            return self.flow_removed_mine(label, expire, overflow, curtime)
        else:
            raise NameError('Error. No such packet-in mode. Exit.')

    """def flow_removed_default(self, label, expire, overflow, curtime):
         return []
    """

    def flow_removed_hybrid(self, label, expire, overflow, curtime):
        instractions = []
        for entry in expire:
            if entry.timeout_type == setting.TIMEOUT_IDLE and entry.priority < 32:
                # print('*remove dependency')
                rule = (entry.priority, entry.match_field)
                deprules = self.ruleset.depset[rule] # dependent ruleset
                for r in deprules:
                    self.parent_count[label][r] -= 1
                    assert self.parent_count[label][r] >= 0
                    if r[0] == 32:
                        entry = element.Entry(setting.FIELD_DSTIP, 32, r[1], None) # exact match rule
                    else:
                        entry = element.Entry(setting.FIELD_DSTPREFIX[r[0]], r[0], r[1], None)
                    instractions.append((setting.INST_DELETE, label, entry))
        return instractions

    def flow_removed_mine(self, label, expire, overflow, curtime):
        instractions = []
        deleted = expire + overflow
        for entry in deleted:
            if entry.timeout_type == setting.TIMEOUT_IDLE or entry.priority < 32:
                # print('*remove dependency')
                rule = (entry.priority, entry.match_field)
                dirdeprules = self.ruleset.dirdepset[rule] # dependent ruleset
                # dirdeprules = self.ruleset.depset[rule]
                for r in dirdeprules:
                    # self.parent_count[label][r] -= 1
                    # assert self.parent_count[label][r] >= 0
                    # if self.parent_count[label][r] > 0 or r in deleted: continue
                    if r[0] == 32:
                        entry = element.Entry(setting.FIELD_DSTIP, 32, r[1], None) # exact match rule
                    else:
                        entry = element.Entry(setting.FIELD_DSTPREFIX[r[0]], r[0], r[1], None)
                    instractions.append((setting.INST_DELETE, label, entry))
        return instractions


if __name__ == '__main__':
    topo = setting.BRIDGE
    soft_labels = setting.BRIDGE_SOFT_LABELS_CORE
    c = Controller(topo, soft_labels)
    for src in c.shortest_pathes:
        for dst in c.shortest_pathes[src]:
            print('%s->%s:' % (src, dst), end='')
            print(c.shortest_pathes[src][dst], end=';')
    # tcp 1500(bit)*2(path len)*0.008(link rate) + 5(hardware switch delay)*2 + 4000(controller delay) = 4034 us        
    assert int(c.get_delay([0, setting.CTRL, 1])) == 4034 
    assert int(c.get_delay([0, 2, 1])) == 69
