# simulate normal OpenFlow architecture


from __future__ import print_function
import element
import setting
import network
import data
    

def simulate(para):
    # n : topology 可以設定網路拓樸樣式，ruleset、topo、generate log traffic都在這裡面設定
    n = para['net']
    # mode : idle, hard, hybrid
    mode = para['mode']
    # log_prefix : log紀錄的前贅字 idle_dqn_0.95之類的
    log_prefix = para['log_prefix']
    # 
    check_interval = para['check_interval']
    # timeout預設機制的數字代號
    predictor_name = para['predictor_name']
    #
    update_interval = para['update_interval']
    #
    flow_per_sec = 0
    if para['flow_per_sec'] is not None :
        flow_per_sec = para['flow_per_sec']
    validate_point = None
    max_flownum = None
    if para['max_flownum'] is not None :
        max_flownum = para['max_flownum']
    if 'validate_point' in para:
        validate_point = para['validate_point']

    c = n.controller
    c.add_predictor(predictor_name)
    # set() : 無序不重複元素集合 
    unit_updates = set()
    n_units_updates = set()
    visited_check_points = set()
    
    flownum = n.traffic.flownum
    d = data.Data()
    curtime = 0
    overflow_num = {}
    for i in range(n.switch_num):
        overflow_num[i] = 0
    overflow_num['total'] = 0
    pktnum = 0
    pktin = 0
    pktsize = 0
    for pkt in n.traffic.pkts:
        if max_flownum is not None :
            if flownum[pktnum] > max_flownum :
                break
        # print('\nprocessing packet#{} {} at {}'.format(pktnum, pkt, curtime))
        sw = n.switches[pkt.src] #src : 是ip的第三個位置 *.*.src.*，在這裡代表是switch的編號
        # print('*arriving source s{}'.format(sw.label))
        hop = 0
        of = 0
        while True:
            if pkt.dst == sw.label:
                # print('*arriving destination s{}'.format(sw.label))
                pkt.path.append(sw.label)
                break

            # expire:超時被移除且必須要通知controller的flow   overflow:因為overflow而被移除的flow
            [expire, overflow] = sw.update(curtime)
            of += len(overflow)
            if len(overflow) > 0:
                overflow_num[sw.label] += len(overflow)
            # print('*update\n**s{}'.format(sw.label))
            # if len(expire) != 0:
            #     print('**expire:')
            #     for entry in expire: print(entry)
            # if len(overflow) != 0:
            #     print('**overflow:')
            #     for entry in overflow: print(entry)

            # controller是否需要對移除的flow做instraction
            instractions = c.flow_removed(sw.label, expire, overflow, curtime, mode)
            # 針對controller的instraction操作
            n.process_ctrl_messages(instractions)

            [pkt, next_hop, reason] = sw.recv_pkt(pkt, curtime)
            # print('*forwarding to {}'.format(next_hop))
            if next_hop == setting.CTRL:
                pktin += 1
                instractions = c.packet_in(sw.label, pkt, reason, curtime, mode)
                n.process_ctrl_messages(instractions)
                # d.predict['timeout'].append({"match_field":instractions[0][2].match_field, "timeout" :instractions[0][2].timeout})
            else:
                sw = n.switches[next_hop]
            hop += 1
            pktsize += pkt.size
            assert hop < 10*len(n.topo)
        # print('*pkt path = {}'.format(pkt.path))

        if predictor_name == setting.PREDICTOR_SIMPLE:
            curtime_s = int(curtime/1e6)*1e6
            if (curtime_s not in unit_updates and 
                curtime_s % update_interval == 0):
                unit_updates.add(curtime_s)
                for label in range(n.switch_num):
                    inst = [(setting.INST_QUERY, setting.INST_OBJ_TABLE, label)]
                    ret = n.process_ctrl_messages(inst)
                    entry_num = ret[setting.INST_OBJ_TABLE]
                    c.predictor.update((setting.INFO_TABLE_SIZE, label, 
                                        curtime_s, entry_num))

            if (curtime_s not in n_units_updates and 
                curtime_s % (setting.ITM_N * update_interval) == 0):
                n_units_updates.add(curtime_s)
                c.predictor.update_t_max()
        
        elif (predictor_name == setting.PREDICTOR_Q or 
              predictor_name == setting.PREDICTOR_DQN):
            curtime_s = int(curtime/1e6)*1e6
            if (curtime_s not in unit_updates and
                curtime_s % update_interval == 0):
                unit_updates.add(curtime_s)
                c.predictor.train()

        fnum = flownum[pktnum]
        pktnum += 1
        overflow_num['total'] += of
        pkttime = c.get_delay(pkt.path, pkt.size) # pkt 傳輸時間
        curtime += pkttime

        flowsize = n.traffic.flowsize[pkt.tp]
        #d.record_fct(pkt.tp, pkttime, flowsize)

        if fnum%check_interval == 0:
            # if fnum not in d.delay['flownum']:
            if fnum not in visited_check_points:
                visited_check_points.add(fnum)
                instractions = [(setting.INST_QUERY, setting.INST_OBJ_ALL, None)]
                ret = n.process_ctrl_messages(instractions)
                totentry = ret[setting.INST_OBJ_ALL]
                totinstall = 0
                for entry in c.install_num:
                    totinstall += c.install_num[entry]
                if validate_point is None:
                    d.record(fnum, curtime, totentry, overflow_num.copy(), pktin, totinstall, pktnum, pktsize)
                elif pktnum >= validate_point:
                    d.record(fnum, curtime, totentry, overflow_num.copy(), pktin, totinstall, pktnum, pktsize)
                
                d.print_checkpoint(fnum, log_prefix+'_checkpoint.txt')

                if 'save_model' in para:
                    c.predictor.save_weights(log_prefix)
        
        
        if flow_per_sec != 0 and fnum%flow_per_sec == 0:
            if (fnum/flow_per_sec)*1e6 > curtime:
                curtime = (fnum/flow_per_sec)*1e6
    d.record_install_num(c.install_num)
    d.record_dep_install_num(c.dep_install_num)
    d.print_data(log_prefix)


    timeout_type = {
        setting.MODE_HARD: 'hard', 
        setting.MODE_IDLE: 'idle',
        setting.MODE_HYBRID: 'hybrid',
        setting.MODE_MINE: 'mine'
    }
    
    # with open('./data/{}.txt'.format(timeout_type[mode]), 'a+') as f:
    #     print('{} {}'.format(flow_per_sec, overflow_num['total']), file=f)

    with open('./data/{}_process_time.txt'.format(timeout_type[mode]), 'a+') as f:
        for i in range(0, len(n.controller.packetin_process_time)):
            print(n.controller.packetin_process_time[i], file=f)

    with open('dep_usage.txt', 'a') as f:
        for i in range(len(n.switches[1].dep_count)):
            if n.switches[1].dep_count[i] > 0:
                print('{} {}'.format(n.switches[1].dep_count[i], n.switches[1].dep_triggered_count[i]), file=f)
    if 'save_model' in para:
        c.predictor.save_model(log_prefix)

    return


def cross_validate():
    for k in range(10):
        topo = setting.BRIDGE
        ruleset_pkl = 'bridge_rule_0.95.pkl'

        n = network.Network(topo, soft_labels = None, ruleset_pkl = ruleset_pkl)

        n.generate_sample_traffic()
        mode = setting.MODE_IDLE
        check_interval = 1

        predictor_name = setting.PREDICTOR_DQN
        
        fold_size = len(n.traffic.pkts) / 10

        log_prefix = './data/test/cross_validate_{}'.format(k)

        validate = n.traffic.pkts[k * fold_size : (k + 1) * fold_size]
        n.traffic.pkts = n.traffic.pkts[ : k * fold_size] + n.traffic.pkts[(k + 1) * fold_size : ] + validate
        
        para = {
            'net': n,
            'mode': mode,
            'log_prefix': log_prefix,
            'check_interval': check_interval,
            'predictor_name': predictor_name,
            'update_interval': setting.DEFAULT_UPDATE,
            'validate_point': 9 * fold_size
        }

        simulate(para)
    
    return


def test_model():
    topo = setting.SINGLE
    ruleset_pkl = setting.SINGLE_RULE_PKL

    n = network.Network(topo, soft_labels = None, ruleset_pkl = ruleset_pkl)

    n.generate_log_traffic(setting.SINGLE_TRAFFIC_LOGFILE)
    mode = setting.MODE_HYBRID
    check_interval = 1000

    predictor_name = setting.PREDICTOR_DQN
        
    log_prefix = './data/model'
        
    para = {
        'net': n,
        'mode': mode,
        'log_prefix': log_prefix,
        'check_interval': check_interval,
        'predictor_name': predictor_name,
        'update_interval': setting.DEFAULT_UPDATE,
        'save_model': True
    }

    simulate(para)

    return


def test_ddos():
    from keras.models import load_model
    import numpy
    model = load_model('./data/model.h5')
    x = [100, 100]
    for hit in range(0, 100, 10):
        x[1] = hit
        inputs = numpy.zeros((1, 2))
        inputs[0] = tuple(x)
        estimated_Q = model.predict(inputs).flatten()
        actcnt = numpy.argmax(estimated_Q)
        print('x = {}; timeout = {}s'.format(x, actcnt + 1))
    return


def test():
    timeout_type = {
        setting.MODE_HARD: 'hard', 
        setting.MODE_IDLE: 'idle',
        setting.MODE_HYBRID: 'hybrid',
    }
    predictor_type = {
        setting.PREDICTOR_DEFAULT: 'no',
        setting.PREDICTOR_SIMPLE: 'itm',
        setting.PREDICTOR_Q: 'q',
        setting.PREDICTOR_DQN: 'dqn'
    }
    print('test')

    mode_arr = [setting.MODE_IDLE]
    predictor_name = setting.PREDICTOR_DQN
    rate = 0.95

    topo = setting.BRIDGE
    ruleset_pkl = 'bridge_rule_{}.pkl'.format(rate)  # rate=1 yields a good result
    net_arr = {}
    for mode in mode_arr:
        n = network.Network(topo, soft_labels=None, ruleset_pkl=None)  # no software switches
        n.generate_sample_traffic()
        net_arr[mode] = n
    
    para_arr = []
    for mode in mode_arr:
        log_prefix = './data/{}_{}_{}'.format(timeout_type[mode], 
            predictor_type[predictor_name], 
            rate)
        para_arr.append({
            'net': net_arr[mode],
            'mode': mode,
            'log_prefix': log_prefix,
            'check_interval': 1,
            'predictor_name': predictor_name,
            'update_interval': setting.DEFAULT_UPDATE
        })

    for cnt in range(len(para_arr)):
        simulate(para_arr[cnt])
   
    return


def single(mode, predictor_name, max_flownum=None, flow_per_sec=0):
    timeout_type = {
        setting.MODE_HARD: 'hard', 
        setting.MODE_IDLE: 'idle',
        setting.MODE_HYBRID: 'hybrid',
        setting.MODE_MINE: 'mine'
    }
    predictor_type = {
        setting.PREDICTOR_DEFAULT: 'no',
        setting.PREDICTOR_SIMPLE: 'itm',
        setting.PREDICTOR_Q: 'q',
        setting.PREDICTOR_DQN: 'dqn'
    }

    topo = setting.SINGLE
    n = network.Network(topo, mode, soft_labels=None, ruleset_pkl=setting.SINGLE_RULE_PKL)
    n.generate_log_traffic(setting.SINGLE_TRAFFIC_LOGFILE)
    
    log_prefix = './data/single_{}_{}_{}'.format(timeout_type[mode], 
                                                 predictor_type[predictor_name],
                                                 int(setting.DEFAULT_TIMEOUT/1e6))
    para = {
        'net': n,
        'mode': mode,
        'log_prefix': log_prefix,
        'check_interval': 1000, #多少flow會記錄一次checkpoint
        'predictor_name': predictor_name,
        'update_interval': setting.DEFAULT_UPDATE,
        # 'update_interval': 1e4,
        'max_flownum' : max_flownum,
        'flow_per_sec' : flow_per_sec
    }

    simulate(para)
    
    return


def cb(mode, predictor_name):
    timeout_type = {
        setting.MODE_HARD: 'hard', 
        setting.MODE_IDLE: 'idle',
        setting.MODE_HYBRID: 'hybrid',
    }
    predictor_type = {
        setting.PREDICTOR_DEFAULT: 'no',
        setting.PREDICTOR_SIMPLE: 'itm',
        setting.PREDICTOR_Q: 'q',
        setting.PREDICTOR_DQN: 'dqn'
    }
    
    topo = setting.SINGLE
    n = network.Network(topo, soft_labels=None, ruleset_pkl=setting.CB_RULE_PKL)
    n.generate_log_traffic(setting.CB_TRACE_LOGFILE)
    
    log_prefix = './data/cb_{}_{}_{}'.format(timeout_type[mode], 
                                             predictor_type[predictor_name],
                                             int(setting.DEFAULT_TIMEOUT/1e6))
    para = {
        'net': n,
        'mode': mode,
        'log_prefix': log_prefix,
        'check_interval': 1000,
        'predictor_name': predictor_name,
        'update_interval': setting.DEFAULT_UPDATE
    }

    simulate(para)
    
    return

def bridge(mode, predictor_name):
    timeout_type = {
        setting.MODE_HARD: 'hard', 
        setting.MODE_IDLE: 'idle',
        setting.MODE_HYBRID: 'hybrid',
    }
    predictor_type = {
        setting.PREDICTOR_DEFAULT: 'no',
        setting.PREDICTOR_SIMPLE: 'itm',
        setting.PREDICTOR_Q: 'q',
        setting.PREDICTOR_DQN: 'dqn'
    }
    
    topo = setting.BRIDGE
    n = network.Network(topo, soft_labels=None, ruleset_pkl=setting.BRIDGE_RULE_PKL)
    n.generate_log_traffic(setting.BRIDGE_TRAFFIC_LOGFILE)
    
    log_prefix = './data/bridge_{}_{}_{}'.format(timeout_type[mode], 
                                             predictor_type[predictor_name],
                                             int(setting.DEFAULT_TIMEOUT/1e6))
    para = {
        'net': n,
        'mode': mode,
        'log_prefix': log_prefix,
        'check_interval': 1000,
        'predictor_name': predictor_name,
        'update_interval': setting.DEFAULT_UPDATE
    }

    simulate(para)
    
    return

def brain(mode, predictor_name):
    timeout_type = {
        setting.MODE_HARD: 'hard', 
        setting.MODE_IDLE: 'idle',
        setting.MODE_HYBRID: 'hybrid',
    }
    predictor_type = {
        setting.PREDICTOR_DEFAULT: 'no',
        setting.PREDICTOR_SIMPLE: 'itm',
        setting.PREDICTOR_Q: 'q',
        setting.PREDICTOR_DQN: 'dqn'
    }
    
    topo = setting.BRAIN
    n = network.Network(topo, soft_labels=None, ruleset_pkl=setting.BRAIN_RULE_PKL)
    n.generate_log_traffic(setting.BRAIN_TRAFFIC_LOGFILE)
    
    log_prefix = './data/brain_{}_{}_{}'.format(timeout_type[mode], 
                                             predictor_type[predictor_name],
                                             int(setting.DEFAULT_TIMEOUT/1e6))
    para = {
        'net': n,
        'mode': mode,
        'log_prefix': log_prefix,
        'check_interval': 1000,
        'predictor_name': predictor_name,
        'update_interval': setting.DEFAULT_UPDATE
    }

    simulate(para)
    
    return

if __name__ == '__main__':
    from sys import argv
    
    timeout_type = {
        0: setting.MODE_HARD, 
        1: setting.MODE_IDLE,
        2: setting.MODE_HYBRID,
        3: setting.MODE_MINE
    }
    predictor_type = {
        0: setting.PREDICTOR_DEFAULT,
        1: setting.PREDICTOR_SIMPLE,
        2: setting.PREDICTOR_Q,
        3: setting.PREDICTOR_DQN
    }

    if len(argv) >= 5:
        sw = int(argv[1])
        mode = int(argv[2])
        predictor_name = int(argv[3])
        setting.DEFAULT_TIMEOUT = int(argv[4])*1e6 # default 5 s
        max_flownum = None
        flow_per_sec = 0
        if len(argv) >= 6:
            max_flownum = int(argv[5])
        if len(argv) >= 7:
            flow_per_sec = int(argv[6])
        if sw == 0:  # run single
            single(timeout_type[mode], predictor_type[predictor_name], max_flownum, flow_per_sec)
        elif sw == 1:  # run cb
            cb(timeout_type[mode], predictor_type[predictor_name])
        elif sw == 2:  # run brain
            brain(timeout_type[mode], predictor_type[predictor_name])
        elif sw == 3:  # run bridge
            bridge(timeout_type[mode], predictor_type[predictor_name])
        else:
            raise NameError('Error. Invalid mode. Exit.')
    else:
        test()
        # cross_validate()
        # test_model()
        # test_ddos()