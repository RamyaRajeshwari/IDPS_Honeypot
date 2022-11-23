package gui;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;

public class PacketContents  implements PacketReceiver{
    public void receivePacket(Packet packet){
        Capture_GUI.TA_OUTPUT.append(packet.toString()+ "\n");
    }
}
