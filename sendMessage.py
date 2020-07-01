from tkinter import *
import tkinter as tk
from tkinter.ttk import Treeview, Style

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, in4_chksum, UDP, ICMP
from scapy.all import *
from scapy.layers.l2 import Ether, ARP


class Application(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.createWidgets()

    def createWidgets(self):
        self.title('GUI 报文编辑器')
        self.geometry('1000x800')
        # PanedWindow可供用户调整的框架类，默认是垂直分割，sashrelief是分割线的样式
        self.mainPanedWindow = PanedWindow(self, sashrelief=RAISED, sashwidth=5)
        # 创建选择发送报文类型的导航树并放在左右分隔窗体的左侧
        self.protocolsTree = Treeview()  # 实例化Treeview
        self.mainPanedWindow.add(self.createprotocolsTree())
        # 创建并将协议编辑器窗体放在左右分隔窗体的右侧
        self.protocolEditorFrame = Frame()
        self.mainPanedWindow.add(self.protocolEditorFrame)
        self.mainPanedWindow.pack(fill=BOTH, expand=1)

    def createprotocolsTree(self):
        """
        生成协议导航树
        :return:
        """
        self.protocolsTree.heading('#0', text='选择发送报文类型', anchor='w')
        # 参数：parent, index, iid=NOne, **kw(父节点，插入的位置，id,显示的文本)
        # 应用层
        applicatoin_layer_tree_entry = self.protocolsTree.insert('', 0, "应用层", text="应用层")
        dns_packet_tree_entry = self.protocolsTree.insert(applicatoin_layer_tree_entry, 1, "DNS数据包", text="DNS数据包")
        # 传输层
        transfer_layer_tree_entry = self.protocolsTree.insert('', 1, "传输层", text="传输层")
        tcp_packet_tree_entry = self.protocolsTree.insert(transfer_layer_tree_entry, 0, "TCP数据包", text="TCP数据包")
        udp_packet_tree_entry = self.protocolsTree.insert(transfer_layer_tree_entry, 1, "UDP数据包", text="UDP数据包")
        # 网络层协议
        ip_layer_tree_entry = self.protocolsTree.insert('', 2, "网络层", text="网络层")
        arp_packet_tree_entry = self.protocolsTree.insert(ip_layer_tree_entry, 0, "ARP数据包", text="ARP数据包")
        ip_packet_tree_entry = self.protocolsTree.insert(ip_layer_tree_entry, 1, "IP数据包", text="IP数据包")
        icmp_packet_tree_entry = self.protocolsTree.insert(ip_layer_tree_entry, 2, "ICMP报文", text="ICMP报文")
        # 网络接口层协议
        ether_layer_tree_entry = self.protocolsTree.insert('', 3, "网络接口层", text="网络接口层")
        mac_frame_tree_entry = self.protocolsTree.insert(ether_layer_tree_entry, 1, "以太网MAC协议", text="以太网MAC协议")
        self.protocolsTree.bind('<<TreeviewSelect>>', self.on_click_protocols_tree)
        style = Style(self)
        # get disabled entry colors
        disabled_bg = style.lookup("TEntry", "fieldbackground", ("disabled",))
        style.map("Treeview",
                  fieldbackground=[("disabled", disabled_bg)],
                  foreground=[("disabled", "gray")],
                  background=[("disabled", disabled_bg)])
        self.protocolsTree.pack()
        return self.protocolsTree

    def on_click_protocols_tree(self, event):
        """
        协议导航树的单击事件响应函数
        :param event:
        :return:
        """
        self.selectedItem = event.widget.selection()
        #         event.widget获取Treeview对象，调用selection获取选择对象名称
        #         清空
        for widget in self.protocolEditorFrame.winfo_children():
            widget.destroy()
        if self.selectedItem[0] == "以太网MAC协议":
            self.createEtherFrameWidgets()
        elif self.selectedItem[0] == "ARP数据包":
            self.createARPWidgets()
        elif self.selectedItem[0] == "IP数据包":
            self.createIPWidgets()
        elif self.selectedItem[0] == "ICMP报文":
            self.createICMPWidgets()
        elif self.selectedItem[0] == "TCP数据包":
            self.createTCPWidgets()
        elif self.selectedItem[0] == "UDP数据包":
            self.createUDPWidgets()
        elif self.selectedItem[0] == "DNS数据包":
            self.createDNSWidgets()

    def create_Scrollbar(self, frame):
        """
        设置滚动多行文本框
        :param frame:
        :return:
        """
        resultTextFrame = Frame(frame)
        self.resultText = Text(resultTextFrame, height=20)
        self.s1 = Scrollbar(resultTextFrame, orient=VERTICAL)
        self.s2 = Scrollbar(resultTextFrame, orient=HORIZONTAL)
        self.s1.pack(side=RIGHT, fill=Y)
        self.s2.pack(side=BOTTOM, fill=X)
        self.s1.config(command=self.resultText.yview)
        self.s2.config(command=self.resultText.xview)
        self.resultText['yscrollcommand'] = self.s1.set
        self.resultText['xscrollcommand'] = self.s2.set
        self.resultText.pack(side=LEFT, fill=BOTH)
        resultTextFrame.pack()
        frame.pack()

    def create_protocol_editor(self, field_names, send, continuesend):
        """
        设置生成每个协议编辑界面的Label、Entry、Button
        :param field_names:
        :param send:
        :param continuesend:
        :return:
        """
        entries = []
        self.protocolFrame = Frame(self.protocolEditorFrame)
        i = 0
        for (key, value) in field_names.items():
            i = i + 1
            if i % 2 != 0:
                row = Frame(self.protocolEditorFrame)
            label = Label(row, text=key, anchor='w')
            text = StringVar(value=value)
            entry = Entry(row, textvariable=text)
            row.pack(side=TOP, padx=5, pady=5)
            label.pack(side=LEFT)
            entry.pack(side=LEFT, expand=YES, fill=X)
            entries.append(entry)
        buttonFrame = Frame(self.protocolEditorFrame)
        sendButton = Button(buttonFrame, text="发送", command=send)
        sendButton.pack(side=LEFT)
        self.continueSendButton = Button(buttonFrame, text='连续发送', command=continuesend)
        self.continueSendButton.pack(side=RIGHT)
        buttonFrame.pack(side=TOP)
        self.create_Scrollbar(self.protocolFrame)
        return entries

    def createEtherFrameWidgets(self):
        """
        以太网编辑界面
        :return:
        """
        mac_fields = {'源MAC：  ': '68:EC:C5:EF:79:87',
                      '目的MAC: ': 'FF:FF:FF:FF:FF:FF',
                      'payload: ': '123456',
                      '发送次数:': '3'}
        self.entries = self.create_protocol_editor(mac_fields, self.sendEtherFrame, self.continueSendEtherFrame)

    def createARPWidgets(self):
        """
        ARP编辑界面
        :return:
        """
        self.arp_fields = {'硬件类型：  ': 1,
                           '协议类型：  ': 2048,
                           '操作码：    ': 1,
                           '硬件长度:   ': 6,
                           '协议长度：  ': 4,
                           '源MAC地址： ': '68:ec:c5:ef:79:87',
                           '源IP地址：  ': '192.168.43.9',
                           '目标MAC地址:': '00:00:00:00:00:00',
                           '目标IP地址：': '100.1.1.0',
                           '发送次数：  ': 3}
        self.entries = self.create_protocol_editor(self.arp_fields, self.sendARPFrame, self.continueSendARPFrame)

    def createIPWidgets(self):
        """
        IP数据包编辑界面
        :return:
        """
        self.IP_fields = {'源MAC地址': '00:00:00:00:00:00',
                          '目的MAC地址': 'ff:ff:ff:ff:ff:ff',
                          'MAC帧类型': '2048',
                          '协议版本：': 4,
                          '首部长度：': 5,
                          '服务类型：': 0,
                          '总长度：': 20,
                          '分片ID：': 1,
                          '分片标志位：': 1,
                          '分片偏移：': 0,
                          '生存时间(TTL)：': 64,
                          '协议类型：': 1,
                          'IP首部校验和：': None,
                          '源IP地址：': '192.168.43.155',
                          '目的IP地址：': '10.5.24.200',
                          '发送次数：': 3,
                          "payload: ": '123456'}
        self.entries = self.create_protocol_editor(self.IP_fields, self.sendIPFrame, self.continueSendIPFrame)

    def createICMPWidgets(self):
        """
        ICMP数据报文编辑界面
        :return:
        """
        self.icmp_fields = {'ICMP类型': 8,
                            'ICMP校验和': None,
                            'IP协议版本：': 4,
                            'IP分片ID：': 1,
                            'IP分片标志位：': 0,
                            'IP分片偏移：': 0,
                            'IP生存时间：': 64,
                            'IP校验和：': None,
                            '源IP地址：': '192.168.43.155',
                            '目的IP地址：': '10.5.24.200',
                            '发送次数': 3}

        self.entries = self.create_protocol_editor(self.icmp_fields, self.sendICMPFrame, self.continueSendICMPFrame)

    def createTCPWidgets(self):
        """
        TCP数据报文编辑界面
        :return:
        """
        self.tcp_fields = {'源端口：': 2000,
                           '目的端口：': 1000,
                           '序列号：': 0,
                           '确认号：': 0,
                           '数据偏移：': 5,
                           '标志：': 0,
                           '窗口大小：': 8192,
                           'TCP校验和：': None,
                           '协议版本：': 4,
                           '首部长度': 5,
                           '服务类型：': 6,
                           '分片ID：': 1,
                           '分片标志位：': 1,
                           '分片偏移：': 0,
                           '生存时间(TTL)：': 64,
                           'IP首部校验和：': None,
                           '源IP地址': '192.168.43.155',
                           '目的IP地址': '192.168.0.1',
                           "发送次数：": 3}
        self.entries = self.create_protocol_editor(self.tcp_fields, self.sendTCPFrame, self.continueSendTCPFrame)

    def createUDPWidgets(self):
        """
         UDP数据报文编辑界面
        :return:
        """
        self.udp_fields = {'源端口：': 2000,
                           '目的端口：': 1000,
                           'UDP校验和：': None,
                           '协议版本：': 4,
                           '首部长度:': 5,
                           '服务类型:': 6,
                           '分片ID：': 1,
                           '分片标志位：': 1,
                           '分片偏移：': 0,
                           '生存时间(TTL)：': 64,
                           'IP首部校验和：': None,
                           '源IP地址': '192.168.43.155',
                           '目的IP地址': '14.215.177.39',
                           "发送次数：": 3}
        self.entries = self.create_protocol_editor(self.udp_fields, self.sendUDPFrame, self.continueSendUDPFrame)

    def createDNSWidgets(self):
        self.dns_fields = {'标识字段id:': 0,
                           '操作类型': 0,
                           '操作码': 0,
                           '域名解析方式': 0,
                           '查询名称': 'www.baidu.com',
                           '公共dns': '114.114.114.114',
                           '发送次数：': '3'
                           }
        self.entries = self.create_protocol_editor(self.dns_fields, self.sendDNSFrame, self.continueSendDNSFrame)

    def getDNSPacket(self):
        """
        构造DNS报文
        :return:
        """
        try:
            dns = DNS()
            dns.id = int(self.entries[0].get())
            dns.qr = int(self.entries[1].get())
            dns.opcode = int(self.entries[2].get())
            dns.rd = int(self.entries[3].get())
            dns.qd = DNSQR(qname=self.entries[4].get())
            udp = UDP()
            ip = IP()
            ip.dst = self.entries[5].get()
            dns_packet = Ether() / ip / udp / dns
            dns_packet.show()
            self.resultText.insert('end', dns_packet.summary() + '\n')
            self.resultText.insert('end', str(dns_packet) + '\n')
            return dns_packet
        except Exception as e:
            print(e.with_traceback())
        finally:
            pass

    def sendDNSFrame(self):
        """
        根据个数发送DNS报文
        :return:
        """
        count = int(self.entries[6].get())
        dns_packet = self.getDNSPacket()
        self.sendPacketFrame(count, dns_packet)

    def continueSendDNSFrame(self):
        """
        连续发送DNS报文
        :return:
        """
        dns_packet = self.getDNSPacket()
        self.continueSendPacketFrame(dns_packet)

    def getICMPPacket(self):
        """
        构造ICMP报文
        :return:
        """
        try:
            icmp_packet = IP() / ICMP()
            icmp_packet.version = int(self.entries[2].get())
            icmp_packet.id = int(self.entries[3].get())
            icmp_packet.flags = int(self.entries[4].get())
            icmp_packet.frag = int(self.entries[5].get())
            icmp_packet.ttl = int(self.entries[6].get())
            # ip_packet.chksum = str(self.entries[7].get())
            icmp_packet.src = str(self.entries[8].get())
            icmp_packet.dst = str(self.entries[9].get())
            icmp_packet.type = int(self.entries[0].get())
            # icmp_packet.chksum = str(self.entries[1].get())
            # 获得数据包的二进制值
            pkg_raw = raw(icmp_packet)
            # 构造数据包，自动计算校验和
            icmp_packet = IP(pkg_raw)
            # 去除数据包的IP首部，并构建ICMP对象，这样可以获得ICMP的校验和
            pkg_icmp = pkg_raw[20:]
            pkg_icmp = ICMP(pkg_icmp)
            print("scapy自动计算的ICMP的校验和为：%04x" % pkg_icmp.chksum)
            self.entries[1].delete(0, END)
            self.entries[1].insert(0, hex(pkg_icmp.chksum))
            self.entries[7].delete(0, END)
            self.entries[7].insert(0, hex(icmp_packet.chksum))
            icmp_packet.show()
            self.resultText.insert('end', icmp_packet.summary() + '\n')
            self.resultText.insert('end', str(icmp_packet) + '\n')
            return Ether() / icmp_packet
        except Exception as e:
            print(e.with_traceback())
        finally:
            pass

    def sendICMPFrame(self):
        """
        根据个数发送ICMP报文
        :return:
        """
        count = int(self.entries[10].get())
        icmp_packet = self.getICMPPacket()
        self.sendPacketFrame(count, icmp_packet)

    def continueSendICMPFrame(self):
        """
        连续发送ICMP报文
        :return:
        """
        icmp_packet = self.getICMPPacket()
        self.continueSendPacketFrame(icmp_packet)

    def getUDPPacket(self):
        """
        构造UDP数据包
        :param self:
        :return:
        """
        try:
            ip_packet = IP()
            ip_packet.version = int(self.entries[3].get())
            ip_packet.ihl = int(self.entries[4].get())
            ip_packet.tos = int(self.entries[5].get())
            ip_packet.id = int(self.entries[6].get())
            # ip_packet.flags = int(self.entries[7].get())
            ip_packet.frag = int(self.entries[8].get())
            ip_packet.ttl = int(self.entries[9].get())
            # ip_packet.chksum = self.entries[10].get()
            ip_packet.src = self.entries[11].get()
            ip_packet.dst = self.entries[12].get()
            udp_packet = UDP()
            udp_packet.sport = int(self.entries[0].get())
            udp_packet.dport = int(self.entries[1].get())
            # udp_packet.chksum = int(self.entries[2].get())
            # scapy自动计算IP、UDP校验和
            # 获得数据包的二进制值
            pkg_raw = raw(ip_packet / udp_packet)
            udp_packet_raw = pkg_raw[20:]
            # 构造数据包，自动计算校验和
            scapy_chksum_IP = IP(pkg_raw).chksum
            scapy_chksum_udp = UDP(udp_packet_raw).chksum
            print("scapy自动计算的UDP校验和为：%04x" % scapy_chksum_udp)
            # 手动计算UDP校验和
            udp_packet.chksum = 0
            packet = ip_packet / udp_packet
            udp_raw = raw(packet)[20:]
            self_chksum = in4_chksum(socket.IPPROTO_UDP, packet[IP], udp_raw)
            print("手动计算的UDP校验和为：%04x" % self_chksum)
            if self_chksum == scapy_chksum_udp:
                print("UDP验证和正确")
            else:
                print("UDP验证和不正确")
            udp_packet.chksum = scapy_chksum_udp
            self.entries[2].delete(0, END)
            self.entries[2].insert(0, hex(scapy_chksum_udp))
            self.entries[10].delete(0, END)
            self.entries[10].insert(0, hex(scapy_chksum_IP))
            udp_packet.show()
            self.resultText.insert('end', udp_packet.summary() + '\n')
            self.resultText.insert('end', str(udp_packet) + '\n')
            return Ether() / ip_packet / udp_packet
        except Exception as e:
            print(e.with_traceback())
        finally:
            pass

    def sendUDPFrame(self):
        """
       根据个数发送UDP报文
       :return:
       """
        count = int(self.entries[13].get())
        udp_to_send = self.getUDPPacket()
        udp_to_send.show()
        self.sendPacketFrame(count, udp_to_send)

    def continueSendUDPFrame(self):
        """
        连续发送UDP报文
        :return:
        """
        udp_to_send = self.getUDPPacket()
        udp_to_send.show()
        self.continueSendPacketFrame(udp_to_send)

    def getTCPPacket(self):
        """
        构造TCP数据包
        :return:
        """
        try:
            ip_packet = IP()
            ip_packet.version = int(self.entries[8].get())
            ip_packet.ihl = int(self.entries[9].get())
            ip_packet.tos = int(self.entries[10].get())
            ip_packet.id = int(self.entries[11].get())
            # ip_packet.flags = int(self.entries[12].get())
            ip_packet.frag = int(self.entries[13].get())
            ip_packet.ttl = int(self.entries[14].get())
            # ip_packet.chksum = self.entries[15].get()
            ip_packet.src = self.entries[16].get()
            ip_packet.dst = self.entries[17].get()
            tcp_packet = TCP()
            tcp_packet.sport = int(self.entries[0].get())
            tcp_packet.dport = int(self.entries[1].get())
            tcp_packet.seq = int(self.entries[2].get())
            tcp_packet.ack = int(self.entries[3].get())
            tcp_packet.dataofs = int(self.entries[4].get())
            tcp_packet.flags = int(self.entries[5].get())
            tcp_packet.window = int(self.entries[6].get())
            # tcp_packet.chksum = self.entries[7].get()
            # scapy自动计算IP、TCP校验和
            # 获得数据包的二进制值
            pkg_raw = raw(ip_packet / tcp_packet)
            tcp_packet_raw = pkg_raw[20:]
            # 构造数据包，自动计算校验和
            scapy_chksum_IP = IP(pkg_raw).chksum
            scapy_chksum_tcp = TCP(tcp_packet_raw).chksum
            print("scapy自动计算的TCP校验和为：%04x" % scapy_chksum_tcp)
            # 手动计算TCP校验和
            tcp_packet.chksum = 0
            packet = ip_packet / tcp_packet
            tcp_raw = raw(packet)[20:]
            self_chksum = in4_chksum(socket.IPPROTO_TCP, packet[IP], tcp_raw)
            print("手动计算的TCP校验和为：%04x" % self_chksum)
            if self_chksum == scapy_chksum_tcp:
                print("TCP验证和正确")
            else:
                print("TCP验证和不正确")
            tcp_packet.chksum = scapy_chksum_tcp
            self.entries[7].delete(0, END)
            self.entries[7].insert(0, hex(scapy_chksum_tcp))
            self.entries[15].delete(0, END)
            self.entries[15].insert(0, hex(scapy_chksum_IP))
            tcp_packet.show()
            self.resultText.insert('end', tcp_packet.summary() + '\n')
            self.resultText.insert('end', str(tcp_packet) + '\n')
            return Ether() / ip_packet / tcp_packet
        except Exception as e:
            print(e.with_traceback())
        finally:
            pass

    def sendTCPFrame(self):
        """
       根据个数发送TCP报文
       :return:
       """
        count = int(self.entries[18].get())
        tcp_to_send = self.getTCPPacket()
        tcp_to_send.show()
        self.sendPacketFrame(count, tcp_to_send)

    def continueSendTCPFrame(self):
        """
        连续发送TCP报文
        :return:
        """
        tcp_to_send = self.getTCPPacket()
        self.continueSendPacketFrame(tcp_to_send)

    def getIPPacket(self):
        """
        构造IP数据包
        :return:
        """
        # chksum = self.entries[9].get()
        try:
            eth = Ether()
            eth.src = self.entries[0].get()
            eth.dst = self.entries[1].get()
            eth.type = int(self.entries[2].get())
            ip_packet = IP()
            ip_packet.versionion = int(self.entries[3].get())
            ip_packet.ihl = int(self.entries[4].get())
            ip_packet.tos = int(self.entries[5].get())
            ip_packet.len = int(self.entries[6].get())
            ip_packet.id = int(self.entries[7].get())
            ip_packet.flags = int(self.entries[8].get())
            ip_packet.frag = int(self.entries[9].get())
            ip_packet.ttl = int(self.entries[10].get())
            ip_packet.proto = int(self.entries[11].get())
            payload = self.entries[16].get()
            ip_packet.src = self.entries[13].get()
            ip_packet.dst = self.entries[14].get()
            # 不含payload计算首部校验和
            if payload == '':
                print("无payload的IP报文")
                ip_packet.show()
                checksum_scapy = IP(raw(ip_packet)).chksum
                # 自主计算验证IP首部检验和并进行填充
                print("scapy自动计算的IP首部检验和是：%04x (%s)" % (checksum_scapy, str(checksum_scapy)))
                # 1.将IP首部和自动设置为0
                ip_packet.chksum = 0
                # 2.生成ip首部的数据字符串
                x = raw(ip_packet)
                ipString = "".join("%02x" % orb(x) for x in x)
                # 3.将ip首部的数据字符串转换成字节数组
                ipbytes = bytearray.fromhex(ipString)
                # 4.调用校验和计算函数计算校验和
                checksum_self = self.IP_headchecksum(ipbytes)
                # 5.进行校验和验证
                print("验证计算IP首部的检验和是：%04x (%s)" % (checksum_self, str(checksum_self)))
            # 含payload计算首部校验和
            else:
                print("含有payload的IP报文")
                ip_packet = ip_packet / payload
                ip_packet.show()
                ip_packet.len = 20 + len(payload)
                checksum_scapy = IP(raw(ip_packet)).chksum
                print("scapy自动计算的IP首部检验和是：%04x (%s)" % (checksum_scapy, str(checksum_scapy)))
                ip_packet.chksum = 0
                ip_packet.ihl = 5
                print('\n 报文长度是：%s' % str(ip_packet.len))
                x = raw(ip_packet)
                ipString = "".join("%02x" % orb(x) for x in x)
                ipbytes = bytearray.fromhex(ipString)
                checksum_self = self.IP_headchecksum(ipbytes[0:ip_packet.ihl * 4])
                print("验证计算IP首部的检验和是：%04x (%s)" % (checksum_self, str(checksum_self)))
            if checksum_self == checksum_scapy:
                print("检验和正确")
            else:
                print("检验和不正确")
            ip_packet.chksum = checksum_self
            self.entries[12].delete(0, END)
            self.entries[12].insert(0, hex(ip_packet.chksum))
            ip_packet.show()
            self.resultText.insert('end', ip_packet.summary() + '\n')
            self.resultText.insert('end', str(ip_packet) + '\n')
            return eth / ip_packet
        except Exception as e:
            print(e.with_traceback())
        finally:
            pass

    def sendIPFrame(self):
        """
        根据个数发送IP报文
        :return:
        """
        count = int(self.entries[15].get())
        ip_to_send = self.getIPPacket()
        ip_to_send.show()

        self.sendPacketFrame(count, ip_to_send)

    def continueSendIPFrame(self):
        """
        连续发送IP报文
        :return:
        """
        ip_to_send = self.getIPPacket()
        self.continueSendPacketFrame(ip_to_send)

    def IP_headchecksum(self, IP_head):
        """
        由IP报文首部计算出首部校验和
        :return:
        """
        checknum = 0
        headlen = len(IP_head)
        if headlen % 2 == 1:
            IP_head += b"\0"
            # print(IP_head)
        i = 0
        while i < headlen:
            # print("IP_head[i:i+2]:"+struct.unpack('!H', IP_head[i:i+2]))
            temp = struct.unpack('!H', IP_head[i:i + 2])[0]
            # print("%04x" % temp)
            checknum += temp
            i += 2
        # 将高16bit与低16位bit相加
        checknum = (checknum >> 16) + (checknum & 0xffff)
        # 将进位到高位的16bit与低16bit再相加
        checknum += checknum >> 16
        return ~checknum & 0xffff

    def getARPPacket(self):
        """
        构造ARP数据包
        :return:
        """
        try:
            arp_packet = ARP()
            arp_packet.hwtype = int(self.entries[0].get())
            arp_packet.ptype = int(self.entries[1].get())
            arp_packet.op = int(self.entries[2].get())
            arp_packet.hwlen = int(self.entries[3].get())
            arp_packet.plen = int(self.entries[4].get())
            arp_packet.hwdst = self.entries[5].get()
            arp_packet.psrc = self.entries[6].get()
            arp_packet.hwsrc = self.entries[7].get()
            arp_packet.pdst = self.entries[8].get()
            arp_packet.show()
            self.resultText.insert('end', arp_packet.summary() + '\n')
            self.resultText.insert('end', str(arp_packet) + '\n')
            return Ether() / arp_packet
        except Exception as e:
            print(e.with_traceback())
        finally:
            pass

    def sendARPFrame(self):
        """
        根据个数发送ARP报文
        :return:
        """
        count = int(self.entries[9].get())
        arp_to_send = self.getARPPacket()
        self.sendPacketFrame(count, arp_to_send)

    def continueSendARPFrame(self):
        """
        连续发送ARP报文
        :return:
        """
        arp_to_send = self.getARPPacket()
        self.continueSendPacketFrame(arp_to_send)

    def getEtherPacket(self):
        """
        构造以太网数据包
        :return:
        """
        try:
            payload = self.entries[2].get()
            ether_packet = Ether() / payload
            ether_packet.src = self.entries[0].get()
            ether_packet.des = self.entries[1].get()
            self.resultText.insert('end', str(ether_packet) + '\n')
            self.resultText.insert('end', ether_packet.summary()+'\n')
            return ether_packet
        except Exception as e:
            print(e.with_traceback())
        finally:
            pass

    def sendEtherFrame(self):
        """
        根据个数发送以太网报文
        :return:
        """
        count = int(self.entries[3].get())
        ether_to_send = self.getEtherPacket()
        self.sendPacketFrame(count, ether_to_send)

    def continueSendEtherFrame(self):
        """
        连续发送以太网报文
        :return:
        """
        ether_to_send = self.getEtherPacket()
        self.continueSendPacketFrame(ether_to_send)

    def sendPacketFrame(self, count, packet):
        """
        根据个数发送数据包，每个协议使用这个功能都需要调用这个函数
        :param count:
        :param packet:
        :return:
        """
        try:
            for i in range(count):
                # verbose=0,不在控制回显'Sent 1 packets'.
                sendp(packet, verbose=0)
                self.resultText.insert('end', '成功发送第' + str(i + 1) + '个报文。\n')
        except ValueError as e:
            print(e.with_traceback())
            self.resultText.tag_config('tag', foreground='blue')
            self.resultText.insert('end', '赋值异常,发送失败\n', 'tag')
            self.resultText.insert('end', '错误：' + repr(e), 'tag')
        except Exception as e:
            print(e.with_traceback())
            self.resultText.tag_config('tag', foreground='red')
            self.resultText.insert('end', '发送数据失败\n', 'tag')
            self.resultText.insert('end', '错误：' + repr(e), 'tag')
        finally:
            pass

    def continueSendPacketFrame(self, packet):
        """
        连续发送数据包的控制模块，每个协议需要使用此功能时都需要调用这个函数
        :param packet:
        :return:
        """
        # 用来终止数据包发送线程的线程事件
        self.stopSpending = threading.Event()
        if self.continueSendButton['text'] == '连续发送':
            t = threading.Thread(target=self.sendPacketThread, args=(packet,))
            t.setDaemon(True)
            t.start()
            self.continueSendButton['text'] = '停止'
        else:
            # 将event的标志设置为True，调用wait方法的所有线程将被唤醒；
            self.stopSpending.set()
            self.continueSendButton['text'] = '连续发送'

    def sendPacketThread(self, packet):
        """
        用于连续发送报文的线程
        :param packet:
        :return:
        """
        # 对发送的数据包次数进行计数，用于计算发送速度
        count = 0
        # 将event的标志设置为False，调用wait方法的所有线程将被阻塞；
        self.stopSpending.clear()
        packet_size = len(packet)
        # 推导数据包的协议类型
        proto_names = ['TCP', 'UDP', 'ICMP', 'IP', 'ARP', 'Ether', 'DNS', 'Unknown']
        packet_proto = ''
        for pn in proto_names:
            if pn in packet:
                packet_proto = pn
                break
        # 开始发送时间点
        begin_time = datetime.now()
        while not self.stopSpending.is_set():  # 判断event事件是否为true
            try:
                # verbose=0,不在控制回显'Sent 1 packets'.
                sendp(packet, verbose=0)
                count = count + 1
                end_time = datetime.now()
                total_bytes = packet_size * count
                bytes_per_second = total_bytes / ((end_time - begin_time).total_seconds()) / 1024
                self.resultText.delete(0.0, 'end')
                self.resultText.insert('end', '已经发送了%d个%s数据包, 已经发送了%d个字节，发送速率: %0.4fkB/s\n' %
                        (count, packet_proto, total_bytes, bytes_per_second))
            except Exception as e:
                self.resultText.tag_config('tag', foreground='red')
                self.resultText.insert('end', "发送数据失败\n", 'tag')
                self.resultText.insert('end', '错误：' + repr(e), 'tag')
                print(e.with_traceback())

app = Application()
app.mainloop()
