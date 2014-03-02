import java.util.Arrays;
import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.ARPPacket;
import java.net.InetAddress;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
class kjsceping{
	static NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	static NetworkInterface device = devices[1];
	static NetworkInterfaceAddress[] addresses = device.addresses;
	static InetAddress srcAddress = addresses[0].address;
	static byte[] srcMac = device.mac_address;
    public static void main(String[] args) throws Exception{
        InetAddress destAddress = InetAddress.getByName("192.168.1.1");
        byte[] destMac = arp(destAddress);
        
        JpcapCaptor captor= JpcapCaptor.openDevice(device,2000,false,3000);
		captor.setFilter("icmp",true);
		JpcapSender sender = captor.getJpcapSenderInstance();
        
        int diff=0;
        
        ICMPPacket icmpp = new ICMPPacket();
        icmpp.type = ICMPPacket.ICMP_ECHO;
        icmpp.code = 0;
        icmpp.id = 0x0001;
        icmpp.seq = 0x0001;
        //icmpp.data = 
        icmpp.setIPv4Parameter(0,false,false,false,0,false,false,false,0,88,64,ICMPPacket.IPPROTO_ICMP,srcAddress,destAddress);
				
		EthernetPacket ether = new EthernetPacket();
		ether.frametype=EthernetPacket.ETHERTYPE_IP;
		ether.src_mac=srcMac; // Set the source MAC address to
		ether.dst_mac=destMac; // Set the destination MAC address
		icmpp.datalink=ether; // Set the Data Link Layer of the
		long start = System.nanoTime();
		System.out.println(start);
		long end = 0;
		sender.sendPacket(icmpp);
		diff++;
		
		while(true){
			ICMPPacket p=(ICMPPacket)captor.getPacket();
			end = System.nanoTime();
			System.out.println(end);
			if(diff!=0)
				if(p==null)
					throw new IllegalArgumentException(destAddress+" did not responed to Echo request");
				//if(p.id==icmpp.id){
				else{
					System.out.println(p.id+"icmp_seq="+p.seq+" time="+Math.round((((float)end-(float)start)/1000000)*100)/100.0+"ms");
					diff--;	
				}
			else return;
		}
    }
    static byte[] arp(InetAddress ip) throws Exception{
    	byte[] broadcast=new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};
    	
		JpcapCaptor captor= JpcapCaptor.openDevice(device,2000,false,3000);
		captor.setFilter("arp",true);
		JpcapSender sender = captor.getJpcapSenderInstance();
		
		ARPPacket arp=new ARPPacket();
		arp.hardtype=ARPPacket.HARDTYPE_ETHER;
		arp.prototype=ARPPacket.PROTOTYPE_IP;
		arp.operation=ARPPacket.ARP_REQUEST;
		arp.hlen=6;
		arp.plen=4;
		
		arp.sender_hardaddr=srcMac;
		arp.sender_protoaddr=srcAddress.getAddress();
		arp.target_hardaddr=broadcast;
		arp.target_protoaddr=ip.getAddress();
		
		EthernetPacket ether=new EthernetPacket();
		ether.frametype=EthernetPacket.ETHERTYPE_ARP;
		ether.src_mac=srcMac;
		ether.dst_mac=broadcast;
		arp.datalink=ether;
		sender.sendPacket(arp);
		
		while(true){
			ARPPacket p=(ARPPacket)captor.getPacket();
				if(p==null)
					throw new IllegalArgumentException(ip+" did not responed to ARP request");
				if(Arrays.equals(p.target_protoaddr,srcAddress.getAddress()))
					return p.sender_hardaddr;
		}
	}
}
