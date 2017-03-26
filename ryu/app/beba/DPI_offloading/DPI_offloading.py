import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

import struct


from ryu.lib import hub

import PacketQueueDPI
from utils import append32bitTimeStampToNow
import FlowTable
from params import *

LOG = logging.getLogger('app.beba.evolution')

#TCP_FLAGS     APRSF
RST =      (0b00100,0b00100)
SYN =      (0b00010,0b11111)
FIN =      (0b00001,0b00001)
ACK =      (0b10000,0b10000)
SYN_ACK =  (0b10010,0b10010)

flow_table = FlowTable.FlowTable()
flow_table.startFlush()

packetQueueDPI = PacketQueueDPI.PacketQueueDPI()
packetQueueDPI.startSendingPacket()


class BebaEvolution(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(BebaEvolution, self).__init__(*args, **kwargs)

    def add_flow(self, datapath, table_id, priority, match, actions):
        if len(actions) > 0:
            inst = [ofparser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                  priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):

        """ switch sent his features, check if Beba supported """
        msg = event.msg
        datapath = msg.datapath

        LOG.info("Configuring switch %d..." % datapath.id)

        #   NO BUFFERING
        req = ofparser.OFPSetConfig(
          datapath=datapath,
          miss_send_len=ofproto.OFPCML_NO_BUFFER)
        datapath.send_msg(req)

        """ Set table 1 as stateful """
        req = bebaparser.OFPExpMsgConfigureStatefulTable(
            datapath=datapath,
            table_id=1,
            stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {ip_src, ip_dst, tcp_src, tcp_dst, ip proto} """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
                                                     ofproto.OXM_OF_TCP_SRC, ofproto.OXM_OF_TCP_DST,
                                                     ofproto.OXM_OF_IP_PROTO],
                                             table_id=1)
        datapath.send_msg(req)

        """ Set update extractor = {ip_src, ip_dst, tcp_src, tcp_dst, ip proto}  """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
                                                     ofproto.OXM_OF_TCP_SRC, ofproto.OXM_OF_TCP_DST,
                                                     ofproto.OXM_OF_IP_PROTO],
                                             table_id=1)
        datapath.send_msg(req)

        """ Set BIT update extractor = {ip_dst, ip_src, tcp_dst, tcp_src, ip proto}  """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_DST, ofproto.OXM_OF_IPV4_SRC,
                                                     ofproto.OXM_OF_TCP_DST, ofproto.OXM_OF_TCP_SRC,
                                                     ofproto.OXM_OF_IP_PROTO],
                                             table_id=1, bit=1)
        datapath.send_msg(req)

        ###########################################################################################
        #HEADER FILEDS:

        ''' HF[0] = OXM_EXP_TIMESTAMP [ms] '''
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
                datapath=datapath,
                table_id=1,
                extractor_id=0,
                field=bebaproto.OXM_EXP_TIMESTAMP
        )
        datapath.send_msg(req)

        ''' HF[1] = OXM_EXP_PKT_LEN'''
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
                datapath=datapath,
                table_id=1,
                extractor_id=1,
                field=bebaproto.OXM_EXP_PKT_LEN
        )
        datapath.send_msg(req)

        ###########################################################################################
        # GLOBAL DATA VARIABLE:

        """ Set GDV[0]=10 - DPI Forward Threshold CTS"""
        req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
                datapath=datapath,
                table_id=1,
                global_data_variable_id=0,
                value=PKT_TO_DPI_CTS
        )
        datapath.send_msg(req)

        """ Set GDV[1]=10 - DPI Forward Threshold STC"""
        req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
            datapath=datapath,
            table_id=1,
            global_data_variable_id=1,
            value=PKT_TO_DPI_STC
        )
        datapath.send_msg(req)

        """ Set GDV[2]=0 - Flow Direction"""
        req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
            datapath=datapath,
            table_id=1,
            global_data_variable_id=2,
            value=0
        )
        datapath.send_msg(req)

        ###########################################################################################
        # CONDITION:

        """ Set condition 0: FDV[0] > GDV[0] (packet_counter > threshold_CTS) """
        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            table_id=1,
            condition_id=0,
            condition=bebaproto.CONDITION_GTE,
            operand_1_fd_id=0,
            operand_2_gd_id=0
        )
        datapath.send_msg(req)

        """ Set condition 1: FDV[0] > GDV[1] (packet_counter > threshold_STC"""
        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            table_id=1,
            condition_id=1,
            condition=bebaproto.CONDITION_GTE,
            operand_1_fd_id=0,
            operand_2_gd_id=1
        )
        datapath.send_msg(req)

        """ Set condition 2: FDV[4] > 0 (TRUE = CTS, FALSE = STC)  """
        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            table_id=1,
            condition_id=2,
            condition=bebaproto.CONDITION_GT,
            operand_1_fd_id=4,
            operand_2_gd_id=2
        )
        datapath.send_msg(req)

        ###########################################################################################
        #STATELESS RULES:

        """ RULE FOR UDP: stateless rule, rule with lowest priority """
        """ If ip_proto=17 && udp_src=53 (DNS reply) then flood() and controller()"""
        match = ofparser.OFPMatch(eth_type=0x800, ip_proto=17, udp_src=53 )
        actions = []
        if NO_DPI == 0:
            # The DPI is present
            if DPI_DIRECTLY_CONNECTED == 1:
                actions = [ ofparser.OFPActionOutput(DPI_PORT) ]
            elif DPI_ON_CONTROLLER == 1:
                actions = [ ofparser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER) ]

        self.add_flow(datapath=datapath,
                      table_id=1,
                      priority=0,
                      match=match,
                      actions=actions)

        """ RULES FOR FORWARDING on Table 1 """
        """ HOST_CLIENT_PORT --> Other port, depending on the params.py """
        match = ofparser.OFPMatch(in_port=HOST_CLIENT_PORT)
        actions = []
        inst = []


        # Check conditions on params.py
        if LOCAL_FORWARDING == 1:
            actions.append(ofparser.OFPActionOutput(NAT_OR_HOST_SERVER_PORT))
        if STATELESS == 1:
            # STATELESS SWITCH --> NO go to table 1
            if NO_DPI == 0:
                if DPI_DIRECTLY_CONNECTED == 1:
                    actions.append(ofparser.OFPActionOutput(DPI_PORT))
                elif DPI_ON_CONTROLLER == 1:
                    actions.append(ofparser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER))
            inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            # STATEFUL SWITCH --> go to table 1
            if len(actions) > 0:
                inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            inst.append(ofparser.OFPInstructionGotoTable(1))


        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
                                  priority=100, match=match, instructions=inst)
        datapath.send_msg(mod)



        """ Other port, depending on the params.py --> HOST_CLIENT_PORT """
        match = ofparser.OFPMatch(in_port=NAT_OR_HOST_SERVER_PORT)
        actions = []
        inst = []


        # Check conditions on params.py
        if LOCAL_FORWARDING == 1:
            actions.append(ofparser.OFPActionOutput(HOST_CLIENT_PORT))
        if STATELESS == 1:
            # STATELESS SWITCH --> NO go to table 1
            if NO_DPI == 0:
                if DPI_DIRECTLY_CONNECTED == 1:
                    actions.append(ofparser.OFPActionOutput(DPI_PORT))
                elif DPI_ON_CONTROLLER == 1:
                    actions.append(ofparser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER))
            inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            # STATEFUL SWITCH --> go to table 1
            if len(actions) > 0:
                inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            inst.append(ofparser.OFPInstructionGotoTable(1))


        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
                                  priority=100, match=match, instructions=inst)
        datapath.send_msg(mod)

        ###########################################################################################
        # STATEFUL RULES:

        ###################################################
        # Connection opening rules:
        """ If state = 0 && SYN==1 THEN update state to 1, fwd(DPI), init_stats, flow_direction=1 """
        match = ofparser.OFPMatch(state=0, eth_type=0x0800, ip_proto=6, tcp_flags=SYN)
        actions = []
        if NO_DPI == 0:
            if DPI_DIRECTLY_CONNECTED == 1:
                actions = [ofparser.OFPActionOutput(DPI_PORT)]
            elif DPI_ON_CONTROLLER == 1:
                actions = [ofparser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        actions.extend([
            #Packet Number
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                   operand_1_fd_id=0, operand_2_cost=1),
            #Start Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=1,
                                                    operand_1_hf_id=0, operand_2_cost=0),
            #End Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=2,
                                                    operand_1_hf_id=0, operand_2_cost=0),
            #Packet Byte
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=3,
                                                    operand_1_hf_id=1, operand_2_cost=0),
            #Flow Direction = 1
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=4,
                                                    operand_1_fd_id=4, operand_2_cost=1),
            bebaparser.OFPExpActionSetState(state=1, table_id=1, idle_timeout=30, idle_rollback=2)
        ])

        self.add_flow(datapath=datapath,
                      table_id=1,
                      priority=5,
                      match=match,
                      actions=actions)

        """ If state = 0 && SYN==1 && ACK==1 THEN update state to 1, fwd(DPI), init_stats, flow_direction=0 """
        match = ofparser.OFPMatch(state=0, eth_type=0x0800, ip_proto=6, tcp_flags=SYN_ACK)
        actions = []
        if NO_DPI == 0:
            if DPI_DIRECTLY_CONNECTED == 1:
                actions = [ofparser.OFPActionOutput(DPI_PORT)]
            elif DPI_ON_CONTROLLER == 1:
                actions = [ofparser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        actions.extend([
            # Packet Number
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                   operand_1_fd_id=0, operand_2_cost=1),
            # Start Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=1,
                                                    operand_1_hf_id=0, operand_2_cost=0),
            # End Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=2,
                                                    operand_1_hf_id=0, operand_2_cost=0),
            # Packet Byte
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=3,
                                                    operand_1_hf_id=1, operand_2_cost=0),
            # Flow Direction = 0
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=4,
                                                    operand_1_fd_id=4, operand_2_cost=0),
            bebaparser.OFPExpActionSetState(state=1, table_id=1, idle_timeout=30, idle_rollback=2)
        ])

        self.add_flow(datapath=datapath,
                      table_id=1,
                      priority=6,
                      match=match,
                      actions=actions)


        ###################################################
        # Rules to match condition on packet counter:

        """ If state=1 && CTS && packet_number < CTS_threshold THEN update_stats and fwd(DPI) """
        match = ofparser.OFPMatch(state=1, condition0=0, condition2=1)
        actions = []
        if NO_DPI == 0:
            if DPI_DIRECTLY_CONNECTED == 1:
                actions = [ofparser.OFPActionOutput(DPI_PORT)]
            elif DPI_ON_CONTROLLER == 1:
                actions = [ofparser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        actions.extend([
            # Packet Number
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                    operand_1_fd_id=0, operand_2_cost=1),
            # End Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=2,
                                                    operand_1_hf_id=0, operand_2_cost=0),
            # Packet Byte
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=3,
                                                    operand_1_hf_id=1, operand_2_fd_id=3)
            ])

        self.add_flow(datapath=datapath,
                      table_id=1,
                      priority=2,
                      match=match,
                      actions=actions)

        """ If state=1 && STC && packet_number < STC_threshold THEN update_stats, fwd(DPI) """
        match = ofparser.OFPMatch(state=1, condition1=0, condition2=0)
        actions = []
        if NO_DPI == 0:
            if DPI_DIRECTLY_CONNECTED == 1:
                actions = [ofparser.OFPActionOutput(DPI_PORT)]
            elif DPI_ON_CONTROLLER == 1:
                actions = [ofparser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        actions.extend([
            # Packet Number
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                   operand_1_fd_id=0, operand_2_cost=1),
            # End Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=2,
                                                   operand_1_hf_id=0, operand_2_cost=0),
            # Packet Byte
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=3,
                                                   operand_1_hf_id=1, operand_2_fd_id=3)
        ])

        self.add_flow(datapath=datapath,
                      table_id=1,
                      priority=2,
                      match=match,
                      actions=actions)


        """ If state=1 && CTS && packet_number >= CTS_threshold THEN update_stats """
        match = ofparser.OFPMatch(state=1, condition0=1, condition2=1)
        actions = [
            # Packet Number
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                    operand_1_fd_id=0, operand_2_cost=1),
            # End Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=2,
                                                    operand_1_hf_id=0, operand_2_cost=0),
            # Packet Byte
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=3,
                                                    operand_1_hf_id=1, operand_2_fd_id=3)
            ]

        self.add_flow(datapath=datapath,
                      table_id=1,
                      priority=2,
                      match=match,
                      actions=actions)

        """ If state=1 && STC && packet_number >= STC_threshold THEN update_stats """
        match = ofparser.OFPMatch(state=1, condition1=1, condition2=0)
        actions = [
            # Packet Number
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                   operand_1_fd_id=0, operand_2_cost=1),
            # End Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=2,
                                                   operand_1_hf_id=0, operand_2_cost=0),
            # Packet Byte
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=3,
                                                   operand_1_hf_id=1, operand_2_fd_id=3)
        ]

        self.add_flow(datapath=datapath,
                      table_id=1,
                      priority=2,
                      match=match,
                      actions=actions)


        ###################################################
        #Closing connection rules

        """ if FIN==1 && state=1 then update state to 0, update_stats"""
        match = ofparser.OFPMatch(state=1, eth_type=0x0800, ip_proto=6, tcp_flags=FIN)
        actions = [
            # Packet Number
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                    operand_1_fd_id=0, operand_2_cost=1),
            # End Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=2,
                                                    operand_1_hf_id=0, operand_2_cost=0),
            # Packet Byte
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=3,
                                                   operand_1_hf_id=1, operand_2_fd_id=3),
            bebaparser.OFPExpActionSetState(state=0, table_id=1, idle_timeout=0, idle_rollback=0)
            ]

        self.add_flow(datapath=datapath,
                      table_id=1,
                      priority=10,
                      match=match,
                      actions=actions)

        """ if RST==1 && state=1 then update state to 0, update_stats, BIT_update to state=0"""
        match = ofparser.OFPMatch(state = 1, eth_type=0x0800, ip_proto=6, tcp_flags=RST)
        actions = [
            bebaparser.OFPExpActionSetState(state=0, table_id=1, idle_timeout=0, idle_rollback=0),
            # Packet Number
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                    operand_1_fd_id=0, operand_2_cost=1),
            # End Timestamp
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=2,
                                                    operand_1_hf_id=0, operand_2_cost=0),
            # Packet Byte
            bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=3,
                                                    operand_1_hf_id=1, operand_2_fd_id=3),
            #BIT UPDATE
            #Bit_update state
            bebaparser.OFPExpActionSetState(state=0, table_id=1, idle_timeout=0, idle_rollback=0, bit=1),
            ]

        self.add_flow(datapath=datapath,
                      table_id=1,
                      priority=11,
                      match=match,
                      actions=actions)

        ###########################################################################################
        #Thread for State Request and Delete

        self.monitor_thread = hub.spawn(self._monitor, datapath)


    ###########################################################################################
    #Thread to make State Request and Delete, to collect flows that have expired timeouts (not closed connections)

    def _monitor(self, datapath):
        while 1:
            hub.sleep(30)

            # Request with removal of the entries
            req = bebaparser.OFPExpStateStatsMultipartRequestAndDelete(
                datapath=datapath,
                table_id=1,
                state=2
            )
            datapath.send_msg(req)

    ###########################################################################################
    # STATE CHANGE NOTIFICATIONS:

    @set_ev_cls(ofp_event.EventOFPExperimenter, MAIN_DISPATCHER)
    def packet_experimenter(self, event):
        msg = event.msg

        if msg.experimenter == 0xBEBABEBA :
            if msg.exp_type == bebaproto.OFPT_EXP_STATE_CHANGED :
                print "STATE CHANGE NOTIFICATION!!"
                data1 = msg.data[:struct.calcsize("!IIIII")]

                # PARSEING the state entry
                stateEntry = OFPStateNotification.parser(msg.data, 0)
                # print("  Table ID: " + str(stateEntry.table_id))
                # print(" Old state: " + str(stateEntry.old_state))
                # print(" New state: " + str(stateEntry.new_state))
                # print("Key length: " + str(stateEntry.key_len))

                # PARSING the key value (5-tuple)
                ip_src = stateEntry.key[:4]
                ip_dst = stateEntry.key[4:8]
                port_src = int(stateEntry.key[8] + (stateEntry.key[9]<<8))
                port_dst = int(stateEntry.key[10] + (stateEntry.key[11]<<8))
                ip_proto = int(stateEntry.key[12])
                # print "IP SRC: " + str(ip_src)
                # print "IP DST: " + str(ip_dst)
                # print "TCP PORT SRC: " + str(port_src)
                # print "TCP PORT DST: " + str(port_dst)
                # print "IP PROTO: " + str(ip_proto)
                #print("************")

                # PARSING flow data variable (statistics)
                flow_data_variable = stateEntry.flow_data_var
                ts1 = append32bitTimeStampToNow(flow_data_variable[1])
                ts2 = append32bitTimeStampToNow(flow_data_variable[2])
                flow_data_variable[1] = ts1
                flow_data_variable[2] = ts2
                # print "PKT_NUMBER: " + str(flow_data_variable[0])
                # print "START_TS: " + str(flow_data_variable[1])
                # print "END_TS: " + str(flow_data_variable[2])
                # print "PKT_BYTES: " + str(flow_data_variable[3])
                # print "FLOW_DIRECTION: " + str(flow_data_variable[4])
                
                
                # print "TS1: " + str(ts1) + "TS2: " + str(ts2)

                # SAVE THE FLOW only if the flow is ended
                if( stateEntry.new_state == 0 ):
                    flow_table.addFlow(tuple(ip_src), tuple(ip_dst), port_src, port_dst, flow_data_variable)
                    

    ###########################################################################################
    # STATE STATISTICS (To Be Collected flows - State 2)

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def packet_stats_reply(self, event):
        msg = event.msg
        print "STATE STATS RECEIVED"
        # State Sync: Parse the response from the switch
        if (msg.body.experimenter == 0xBEBABEBA):
            if (msg.body.exp_type == bebaproto.OFPMP_EXP_STATE_STATS_AND_DELETE):
                data = msg.body.data
                #print binascii.hexlify(data)
                t = bebaparser.OFPStateStats.parser(data, 0)
                if (t != []):
                    for index in range(len(t)):
                        # print bebaparser.state_entry_key_to_str(t[index])
                        k = map(lambda x: hex(x), t[index].entry.key)
                        # print k
                        fd = map(lambda x: x, t[index].entry.flow_data_var)
                        # print fd

                        ts1 = append32bitTimeStampToNow(fd[1])
                        ts2 = append32bitTimeStampToNow(fd[2])
                        fd[1] = ts1
                        fd[2] = ts2

                        # print ("TIMESTAMP1: " + str(ts1) + "  TIMESTAMP2: " + str(ts2))
                        # print("State : " + str(t[index].entry.state))
                        # print("Key   : " + str(t[index].entry.key))
                        # print("FlowDataVar: " + str(fd))
                        # print("*********")
                        if(t[index].entry.key_count == 13):
                            ip_src = tuple(t[index].entry.key[:4])
                            ip_dst = tuple(t[index].entry.key[4:8])
                            port_src = t[index].entry.key[8] + (t[index].entry.key[9] << 8)
                            port_dst = t[index].entry.key[10] + (t[index].entry.key[11] << 8)
                            ip_proto = t[index].entry.key[12]
                            flow_table.addFlow(ip_src, ip_dst, port_src, port_dst, fd)

    ###########################################################################################
    # PACKET IN:

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, event):
        #Here I have to redirect the packet to the DPI
        packetQueueDPI.addPacket(event.msg.data)

###########################################################################################
# Parser for the State Notification
class OFPStateNotification(object):
	
    def __init__(self, table_id=None, old_state=None, new_state=None, state_mask=None,
                 key_len=None, key=None, flow_data_var=None ):
        super(OFPStateNotification, self).__init__()

        self.table_id=table_id
        self.old_state=old_state
        self.new_state=new_state
        self.state_mask=state_mask
        self.key_len=key_len
        self.key=key
        self.flow_data_var=flow_data_var

    @classmethod
    def parser(cls, buf, offset):
        entry = OFPStateNotification()

        (entry.table_id, entry.old_state, entry.new_state, entry.state_mask, entry.key_len) = \
            struct.unpack_from("!IIIII", buf, offset)
        offset += 20
        entry.key = []
        if entry.key_len <= bebaproto.MAX_KEY_LEN:
            for f in range(entry.key_len):
                key = struct.unpack_from("!B", buf, offset)
                entry.key.append(key[0])
                offset += 1
        offset += (bebaproto.MAX_KEY_LEN - entry.key_len)

        entry.flow_data_var = []
        for f in range(bebaproto.MAX_FLOW_DATA_VAR_NUM):
            flow_data = struct.unpack_from("<I", buf, offset)
            entry.flow_data_var.append(flow_data[0])
            offset += 4
        return entry