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
}
class kjsceping{
	static NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	static NetworkInterface device = devices[0];
	static NetworkInterfaceAddress[] addresses = device.addresses;
	public static void main(String args[]) throws Exception{
		Global.srcAddress = addresses[0].address;
		Global.srcMac = device.mac_address;
	    Global.destAddress = InetAddress.getByName(args[0]);
        Global.destMac = arp(Global.destAddress);
        JpcapCaptor captor= JpcapCaptor.openDevice(device,10000,false,30000);
        captor.setFilter("icmp",true);
		//captor.setFilter("icmp && ip=="+Global.srcAddress.toString(),true);
		Sender icmpSender = new Sender(captor);
		Thread senderThread = new Thread(icmpSender);
		senderThread.start();
		Receiver icmpReceiver = new Receiver(captor);
		Thread receiverThread = new Thread(icmpReceiver);
		receiverThread.start();		        
    }
	static byte[] arp(InetAddress ip) throws Exception{
    	byte[] broadcast=new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};
    	
		JpcapCaptor captor= JpcapCaptor.openDevice(device,10000,false,60000);
		captor.setFilter("arp",true);
		JpcapSender sender = captor.getJpcapSenderInstance();
		
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
		
		EthernetPacket ether=new EthernetPacket();
		ether.frametype=EthernetPacket.ETHERTYPE_ARP;
		ether.src_mac=Global.srcMac;
		ether.dst_mac=broadcast;
		arp.datalink=ether;
		sender.sendPacket(arp);
		
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
	short seq = 0;
	short id = (short)(Math.random()%32767);
	Sender(JpcapCaptor c){
		sender=c.getJpcapSenderInstance();
	}
	public void run(){
		try{
			while(true){
				ICMPPacket icmpp = new ICMPPacket();
		        icmpp.type = ICMPPacket.ICMP_ECHO;
		        icmpp.code = 0;
		        icmpp.id = id;
		        icmpp.seq = seq++;
		        icmpp.data = (kjsceping.getRandomHexString(48)).getBytes();
		        icmpp.setIPv4Parameter(0,false,false,false,0,false,false,false,0,88,64,ICMPPacket.IPPROTO_ICMP,Global.srcAddress,Global.destAddress);
		        
				EthernetPacket ether = new EthernetPacket();
				ether.frametype=EthernetPacket.ETHERTYPE_IP;
				ether.src_mac=Global.srcMac;
				ether.dst_mac=Global.destMac;
				icmpp.datalink=ether;
				
				long start = System.nanoTime();
				sender.sendPacket(icmpp);
				Thread.sleep(1000);
			}
		}catch(Exception e) {
			System.out.println(e);	
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
				ICMPPacket p=(ICMPPacket)captor.getPacket();
				long end = System.nanoTime();
				if(p==null)
					throw new IllegalArgumentException(Global.destAddress+" did not responed to Echo request");
				else{
					if(p.src_ip.toString().equals(Global.destAddress.toString())){
						//System.out.println("icmp_seq="+p.seq+" ttl="+p.hop_limit+" time="+Math.round((((float)end-(float)start)/1000000)*100)/100.0+"ms");
						System.out.println("icmp_seq="+p.seq+" ttl="+p.hop_limit+" time="+end+"ms");
					}
				}
			}
		}catch(Exception e) {
			System.out.println(e);	
		}
	}
}
