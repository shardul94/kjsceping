import java.util.Arrays;
import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.ARPPacket;
import jpcap.packet.IPPacket;
import java.net.InetAddress;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import java.util.Random;
class Global {
    public static InetAddress srcAddress;
    public static InetAddress destAddress;
    public static byte[] srcMac;
	public static byte[] destMac;
	public static long[] sentTime;
	public static String[] sentData;
}
class kjsceping{
	static NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	static NetworkInterface device = devices[0];
	static NetworkInterfaceAddress[] addresses = device.addresses;
	public static void main(String args[]) throws Exception{
		Global.srcAddress = addresses[0].address;
		Global.srcMac = device.mac_address;
	    Global.destAddress = InetAddress.getByName(args[0]);
	    String tempString[] = Global.destAddress.toString().split("/");
	    System.out.println("PING "+args[0]+" ("+tempString[1]+") 56(84) bytes of data.");
        Global.destMac = arp(Global.destAddress);
        Global.sentTime = new long[32768];
		Global.sentData = new String[32768];
        JpcapCaptor captor= JpcapCaptor.openDevice(device,10000,false,30000);
        captor.setFilter("icmp",true);
		Sender icmpSender = new Sender(captor);
		Thread senderThread = new Thread(icmpSender);
		senderThread.start();
		Receiver icmpReceiver = new Receiver(captor);
		Thread receiverThread = new Thread(icmpReceiver);
		receiverThread.start();		        
    }
	static byte[] arp(InetAddress ip) throws Exception{
    	byte[] broadcast=new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};
    	//Create captor for capturing
		JpcapCaptor captor= JpcapCaptor.openDevice(device,10000,false,60000);
		captor.setFilter("arp",true);
		JpcapSender sender = captor.getJpcapSenderInstance();
		//Create ARP Packet
		ARPPacket arp=new ARPPacket();
		arp.hardtype=ARPPacket.HARDTYPE_ETHER;
		arp.prototype=ARPPacket.PROTOTYPE_IP;
		arp.operation=ARPPacket.ARP_REQUEST;
		arp.hlen=6;
		arp.plen=4;
		arp.sender_hardaddr=Global.srcMac;
		arp.sender_protoaddr=Global.srcAddress.getAddress();
		arp.target_hardaddr=new byte[]{(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0};
		arp.target_protoaddr=ip.getAddress();
		//Create Ethernet Packet
		EthernetPacket ether=new EthernetPacket();
		ether.frametype=EthernetPacket.ETHERTYPE_ARP;
		ether.src_mac=Global.srcMac;
		ether.dst_mac=broadcast;
		arp.datalink=ether;
		sender.sendPacket(arp);
		//For capturing packet
		while(true){
			ARPPacket p=(ARPPacket)captor.getPacket();
				if(p==null)
					throw new IllegalArgumentException(ip+" did not responed to ARP request");
				if(Arrays.equals(p.target_protoaddr,Global.srcAddress.getAddress()))
					return p.sender_hardaddr;
		}
	}
	static String getRandomHexString(int numchars){
        Random r = new Random();
        StringBuffer sb = new StringBuffer();
        while(sb.length() < numchars){
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString().substring(0, numchars);
    }
}
class Sender implements Runnable{
	JpcapSender sender;
	short seq = 1;
	short id = (short)(Math.random()*32768%32768);
	Sender(JpcapCaptor c){
		sender=c.getJpcapSenderInstance();
	}
	public void run(){
		try{
			while(true){
				//Create ICMP Packet
				ICMPPacket icmpp = new ICMPPacket();
		        icmpp.type = ICMPPacket.ICMP_ECHO;
		        icmpp.code = 0;
		        icmpp.id = id;
		        icmpp.seq = seq;
		        String tempData = kjsceping.getRandomHexString(48);
		        icmpp.data = tempData.getBytes();
		        icmpp.setIPv4Parameter(0,false,false,false,0,false,false,false,0,88,64,ICMPPacket.IPPROTO_ICMP,Global.srcAddress,Global.destAddress);
		        //Create Ethernet Packet
				EthernetPacket ether = new EthernetPacket();
				ether.frametype=EthernetPacket.ETHERTYPE_IP;
				ether.src_mac=Global.srcMac;
				ether.dst_mac=Global.destMac;
				icmpp.datalink=ether;
				//Send Packet and record Time and Data
				Global.sentTime[seq] = System.nanoTime();
				Global.sentData[seq] = tempData;
				sender.sendPacket(icmpp);
				seq++;
				if(seq==32768) seq=0;
				Thread.sleep(1000);
			}
		}catch(Exception e) {
			e.printStackTrace();	
		}
	}
}
class Receiver implements Runnable{
	JpcapCaptor captor;
	Receiver(JpcapCaptor c){
		captor = c;
	}
	public void run(){
		try{
			while(true){
				//Receive Packet
				ICMPPacket p=(ICMPPacket)captor.getPacket();
				long end = System.nanoTime();
				if(p==null)
					throw new IllegalArgumentException(Global.destAddress+" did not responed to Echo request");
				else{
					//Check if packet has same id and is for our ip
					boolean ipCheck = p.src_ip.toString().equals(Global.destAddress.toString()) && p.dst_ip.toString().equals(Global.srcAddress.toString());
					if(ipCheck){
						String temp1 = Global.sentData[p.seq];
						String temp2 = new String(p.data);
						boolean dataCheck = temp1.equalsIgnoreCase(temp2);
						if(dataCheck){
							long time1 = (end-Global.sentTime[p.seq])/10000;
							double time = time1/100.0;
						    String tempString[] = Global.destAddress.toString().split("/");
							System.out.println("64 bytes from "+tempString[1]+": icmp_req="+p.seq+" ttl="+p.hop_limit+" time="+time+"ms");
						}
					}
				}
			}
		}catch(Exception e) {
			e.printStackTrace();	
		}
	}
}