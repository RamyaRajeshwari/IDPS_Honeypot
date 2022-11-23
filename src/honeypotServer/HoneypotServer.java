package honeypotServer;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import gui.Capture_GUI;

public class HoneypotServer {
	Socket clientSocket = null;
	ServerSocket serverSocket = null;
	Capture_GUI gui = new Capture_GUI();
	private int i=0;
	public void runServer() throws IOException
	{
		try {
			serverSocket = new ServerSocket (23);
			System.out.println("server started....on FTP 23");
			while(true)
			{
				clientSocket = serverSocket.accept();
				new Thread(new HoneypotServerThread(clientSocket)).start();
				System.out.println("socket connected");
				incrementConnections();
			}
		} 
		catch (Exception e) {}
	}

	public void incrementConnections() {
		i++;
		System.out.println("reach");
		if(gui != null) 
		{
			gui.setNumberConnections(i);
			System.out.println("lo");
		}
		System.out.println("executed ");
		System.out.println(i);
	}
	
	public static void main(String[] args) throws IOException {
		new HoneypotServer().runServer();
	}
}
