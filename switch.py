#  implement basic hw switch functions


from __future__ import print_function
import element
import traffic
import setting


class Switch:
    def __init__(self, label, mode, sw_type=setting.TYPE_HARDWARE):
        # switch的編號
        self.label = label
        self.sw_type = sw_type
        self.mode = mode
        self.flow_table = {}
        self.table_size = 0
        self.fix_dep_pro = False
        self.get_usage = False
        self.default_action = [(setting.ACT_FWD, setting.CTRL)]
        self.ruleset = element.de_serialize(setting.SINGLE_RULE_PKL)
        self.parent = {}
        self.dep_count = []
        self.dep_triggered_count = []

        for rp in self.ruleset.dirdepset:
            if self.ruleset.dirdepset[rp] is not None:
                for rc in self.ruleset.dirdepset[rp]:
                    self.parent[rc] = rp

    def get_entry_list(self):
        entry_list = []
        for field in self.flow_table:
            for match_field in self.flow_table[field]:
                entry_list.append(self.flow_table[field][match_field])
        return entry_list

    def __repr__(self):
        return 'Switch()'

    def __str__(self):
        s = 's{}, type:{}'.format(self.label, self.sw_type)
        entry_list = self.get_entry_list()
        for entry in entry_list:        
            s = '{}\n{}'.format(s, entry.__str__())
        return s

    def set_sw_type(self, sw_type):
        self.sw_type = sw_type
        return 0

    def set_default_action(self, default_action):
        self.default_action = default_action
        return 0

    def delete_entry(self, entry):
        # print('**delete entry at s{}:\n{}'.format(self.label, entry))
        ret = self.flow_table[entry.field].pop(entry.match_field, None)
        if ret is None: 
            print('Error. No such key in the flow table. Ignore.')
        else:
            self.table_size -= 1
        # del self.flow_table[entry.field][entry.match_field]
        return 0

    #更新switch狀態
    def update(self, now=None):
        expire = []
        if now is not None:
            # 將超時的flow移到to_remove這個list，並且從switch刪除flow entry
            to_remove = []
            # 比對flow table
            for field in self.flow_table:
                for match_field in self.flow_table[field]:
                    entry = self.flow_table[field][match_field]

                    # select expired rule
                    if entry.timeout_type == setting.TIMEOUT_IDLE and entry.ts_last_trigger+entry.timeout <= now:
                        to_remove.append(entry)
                        # 確認是否有FLAG_REMOVE_NOTIFY，timeout後要通知controller，若要就放進expire
                        if (entry.flag is not None and 
                            entry.flag == setting.FLAG_REMOVE_NOTIFY):
                            expire.append(entry)
                        ###
                        if self.get_usage == True:
                            rule = (entry.priority, entry.match_field)
                            deprules = self.ruleset.depset[rule]                   
                            total_count = 0
                            not_triggered_count = 0
                            for r in deprules:
                                if r[0] == 32:
                                    f = setting.FIELD_DSTIP
                                else:
                                    f = setting.FIELD_DSTPREFIX[r[0]]
                                # check if this rule is in flowtable
                                if f in self.flow_table:
                                    if r[1] in self.flow_table[f]:
                                        total_count += 1
                                        if self.flow_table[f][r[1]].counter > 0: not_triggered_count += 1
                            self.dep_count.append(total_count)
                            self.dep_triggered_count.append(not_triggered_count)
                        ###




                    elif ( entry.timeout_type == setting.TIMEOUT_HARD or entry.timeout_type == setting.TIMEOUT_HARD_LEAD ) and entry.ts+entry.timeout <= now:
                        to_remove.append(entry)
                        if (entry.flag is not None and 
                            entry.flag == setting.FLAG_REMOVE_NOTIFY):
                            expire.append(entry)

            for entry in to_remove:
                self.delete_entry(entry)

        max_size = setting.FLOW_TABLE_SIZE[self.sw_type]

        # 將overflow被刪除的flow移到overflow list，並且從switch刪除flow entry
        overflow = []
        if self.table_size >= max_size:
            entry_list = self.get_entry_list()

            if self.fix_dep_pro == False:
                # both use lru make stats look great. FIFO造成所有方法都變差，並且hybrid會差於hard、idle
                if self.mode == setting.MODE_MINE:
                    # LRU
                    overflow = sorted(entry_list, key=lambda e: e.ts_last_trigger)[:(self.table_size-max_size)]
                else:
                    # LRU
                    overflow = sorted(entry_list, key=lambda e: e.ts_last_trigger)[:(self.table_size-max_size)]
                    # FIFO
                    # overflow = sorted(entry_list, key=lambda e: e.ts)[:(self.table_size-max_size)]
            
            # TODO:MINE dependency problem
            elif self.fix_dep_pro == True:
                if self.mode != setting.MODE_IDLE:
                    # LRU without dependency problem: remove least used rules.
                    overflow = []
                    evict_n = self.table_size - max_size
                    entry_list = sorted(entry_list, key=lambda e: e.ts_last_trigger)
                    for entry in entry_list:
                        if len(overflow) >= evict_n: break
                        if entry.timeout_type == setting.TIMEOUT_IDLE or entry.timeout_type == setting.TIMEOUT_HARD_LEAD:
                            overflow.append(entry)
                            rule = (entry.priority, entry.match_field)
                            
                            total_count = 0
                            not_triggered_count = 0
                            deprules = self.ruleset.depset[rule]
                            for r in deprules:
                                if r[0] == 32:
                                    field = setting.FIELD_DSTIP
                                else:
                                    field = setting.FIELD_DSTPREFIX[r[0]]
                                # check if this rule is in flowtable
                                if field in self.flow_table:
                                    if r[1] in self.flow_table[field]:
                                        overflow.append(self.flow_table[field][r[1]])
                                        if self.get_usage == True:
                                            total_count += 1
                                            if self.flow_table[field][r[1]].counter > 0: not_triggered_count += 1
                            if self.get_usage == True:
                                self.dep_count.append(total_count)
                                self.dep_triggered_count.append(not_triggered_count)
                else: 
                    overflow = sorted(entry_list, key=lambda e: e.ts_last_trigger)[:(self.table_size-max_size)]
            # # #
            for entry in overflow:
                self.delete_entry(entry)
        
        return [expire, overflow]

    def add_entry(self, entry):
        
        def add_fast_entry(entry):
            if entry.field in self.flow_table:
                self.flow_table[entry.field][entry.match_field] = entry
            else:
                self.flow_table[entry.field] = {entry.match_field: entry}
            return

        if entry.field in self.flow_table:
            if entry.match_field in self.flow_table[entry.field]:
                old_entry = self.flow_table[entry.field][entry.match_field]
                # exists old entry; update with the new entry
                if entry.priority >= old_entry.priority:
                    # print('**overwrite entry at s{}:\n{}'.format(self.label, entry))                    
                    self.flow_table[entry.field][entry.match_field] = entry
                    return old_entry
                return None

        """update the flow table manually
        [expire, overflow] = self.update(now)"""
        add_fast_entry(entry)
        self.table_size += 1
        # print('**add entry at s{}:\n{}'.format(self.label, entry))
        return None

    def get_match_entry(self, pkt):
        match_entry = element.Entry(None, -1, None, None)

        def comp_entry(new_entry, old_entry):
            if new_entry.priority > old_entry.priority:
                return new_entry
            elif new_entry.priority == old_entry.priority:  # TODO: ECMP
                return old_entry
            else:
                return old_entry

        # fast match (exact matching)
        pkt_attr = {
            setting.FIELD_TP: pkt.tp,
            setting.FIELD_DSTIP: pkt.dstip
        }

        for field in pkt_attr:
            if field in self.flow_table:
                attr = pkt_attr[field]
                if attr in self.flow_table[field]:
                    entry = self.flow_table[field][attr]
                    match_entry = comp_entry(entry, match_entry)

        # slow match (wildcard matching for dstip)
        if match_entry.priority == -1:
            for prefix in setting.FIELD_DSTPREFIX:
                field = setting.FIELD_DSTPREFIX[prefix]
                if field in self.flow_table:
                    attr = element.int2ip(element.get_ip_range(pkt.dstip, prefix)[0])
                    if attr in self.flow_table[field]:
                        entry = self.flow_table[field][attr]
                        match_entry = comp_entry(entry, match_entry)
        
        return match_entry

    def get_match_action(self, pkt, now=None):
        match_entry = self.get_match_entry(pkt)
        # print('**match entry: {}'.format(match_entry))
        if match_entry.action is None:
            return None
        else:
            match_entry.counter += 1
            if now is not None and match_entry.ts is not None:    
                match_entry.ts_last_trigger = now

            # 更新 parent 的 ts_last_trigger 
            # TODO:MINE  dependency problem
            if self.fix_dep_pro == True:
                if self.mode != setting.MODE_IDLE:
                    if match_entry.timeout_type != setting.TIMEOUT_IDLE or match_entry.timeout_type != setting.TIMEOUT_HARD_LEAD:
                        self.update_ts((match_entry.priority, match_entry.match_field), now)
                    
            # if self.mode == setting.MODE_MINE or self.mode == setting.MODE_HYBRID:
            #     if match_entry.timeout_type != setting.TIMEOUT_IDLE or match_entry.timeout_type != setting.TIMEOUT_HARD_LEAD:
            #         ip24 = element.int2ip(element.get_ip_range(match_entry.match_field, 24)[0])
            #         ip28 = element.int2ip(element.get_ip_range(match_entry.match_field, 28)[0])
            #         if setting.FIELD_DSTPREFIX[24] in self.flow_table:
            #             if ip24 in self.flow_table[setting.FIELD_DSTPREFIX[24]]: self.flow_table[setting.FIELD_DSTPREFIX[24]][ip24].ts_last_trigger = now
            #         elif setting.FIELD_DSTPREFIX[28] in self.flow_table:
            #             if ip28 in self.flow_table[setting.FIELD_DSTPREFIX[28]]: self.flow_table[setting.FIELD_DSTPREFIX[28]][ip28].ts_last_trigger = now   
                
            # # #

            return match_entry.action

    def update_ts(self, rule_child, now):
        if rule_child in self.parent:
            if self.parent[rule_child] is not None:
                field = setting.FIELD_DSTPREFIX[self.parent[rule_child][0]]
                rule = self.parent[rule_child][1]
                if field in self.flow_table:
                    if rule in self.flow_table[field]: 
                        self.flow_table[field][rule].ts_last_trigger = now
                        self.update_ts(self.parent[rule_child], now)

    # simulate switch recive packet
    def recv_pkt(self, pkt, now=None):
        action = self.get_match_action(pkt, now)  # action = [(type, value), ...]
        reason = setting.OFPR_ACTION
        if action is None:
            action = self.default_action
            reason = setting.OFPR_NO_MATCH
        for act in action:
            act_type = act[0]
            if act_type == setting.ACT_TAG:
                pkt.label = act[1]
            elif act_type == setting.ACT_FWD:
                next_hop = act[1]
            else:
                raise NameError('Error. No such act type. Exit.')

        pkt.path.append(self.label)

        if next_hop == setting.CTRL:
            pkt.path.append(setting.CTRL)
        
        return [pkt, next_hop, reason]


if __name__ == '__main__':
    label = 0
    sw = Switch(label)
    # basic tests
    entry = element.Entry(setting.FIELD_DSTIP, 32, '1.2.3.4',
                          [(setting.ACT_FWD, 1)])
    sw.add_entry(entry)
    assert sw.table_size == 1
    pkt = traffic.Packet(('0.0.0.0', '1.2.3.4'))
    [pkt, next_hop] = sw.recv_pkt(pkt)
    assert next_hop == 1
    entry = element.Entry(setting.FIELD_DSTPREFIX[24], 24, '1.2.3.0',
                          [(setting.ACT_FWD, 2)])
    sw.add_entry(entry)
    pkt = traffic.Packet(('0.0.0.0', '1.2.3.5'))
    [pkt, next_hop] = sw.recv_pkt(pkt)
    assert next_hop == 2
    
    setting.FLOW_TABLE_SIZE[setting.TYPE_HARDWARE] = 1
    [_, overflow] = sw.update()
    assert len(overflow) == 1
    assert sw.table_size == 1
    sw.delete_entry(element.Entry(setting.FIELD_DSTIP, 32, '1.1.1.1', 
                                  None))
    assert sw.table_size == 1

    setting.FLOW_TABLE_SIZE[setting.TYPE_HARDWARE] = 0
    sw.update()
    setting.FLOW_TABLE_SIZE[setting.TYPE_HARDWARE] = 3000

    # timeout tests
    entry = element.Entry(setting.FIELD_DSTIP, 32, '1.2.3.4',
                          [(setting.ACT_FWD, 1)], setting.FLAG_REMOVE_NOTIFY, 
                          0, 10, setting.TIMEOUT_IDLE)
    sw.add_entry(entry)
    pkt = traffic.Packet(('0.0.0.0', '1.2.3.4'))
    [pkt, next_hop] = sw.recv_pkt(pkt, 5)
    sw.update(10)
    assert sw.table_size == 1
    [expire, _] = sw.update(15)
    assert len(expire) == 1
    assert sw.table_size == 0
    
    # update tests
    for i in range(10):
        entry = element.Entry(setting.FIELD_DSTIP, 32, '1.2.3.4',
                            [(setting.ACT_FWD, 1)], setting.FLAG_REMOVE_NOTIFY, 
                            i, 10, setting.TIMEOUT_IDLE)
        sw.add_entry(entry)
        assert sw.table_size == 1

    for i in range(10):
        entry = element.Entry(setting.FIELD_DSTIP, 32, '1.2.3.{}'.format(i),
                            [(setting.ACT_FWD, 1)], setting.FLAG_REMOVE_NOTIFY, 
                            i, 10, setting.TIMEOUT_IDLE)
        sw.add_entry(entry)
    assert sw.table_size == 10
    [expire, _] = sw.update(10)
    assert sw.table_size == 9
    assert expire[0].ts == 0
    setting.FLOW_TABLE_SIZE[setting.TYPE_HARDWARE] = 8
    [_, overflow] = sw.update(10)
    assert overflow[0].ts == 1
    entry_list = sw.get_entry_list()
    assert len(entry_list) == 8

    """pressure tests
    """
    setting.FLOW_TABLE_SIZE[setting.TYPE_HARDWARE] = 1500
    for i in range(255):
        for j in range(255):
            entry = element.Entry(setting.FIELD_DSTIP, 32, '1.2.{}.{}'.format(i, j),
                                [(setting.ACT_FWD, 1)])
            sw.add_entry(entry)
