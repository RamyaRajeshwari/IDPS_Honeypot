package honeypotServer;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;
		
public class HoneypotServerThread implements Runnable {
	Socket clientSocket;

	HoneypotServerThread(Socket clientSocket) {
		this.clientSocket=clientSocket;
	}

	public void run() 
	{
		try {
			Scanner in1 = new Scanner(clientSocket.getInputStream());
			String mes;
		
			PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
		
			out.println("220 Service ready for new user.");
			while (true) {
				if (in1.hasNext()) {
					mes = in1.nextLine();
					System.out.println("hacker message :" + mes);
					if(mes .equals("akash"))
					{
						out.println("331 User name ok, need password.");
					}
					else if(mes.equals("akashpass")) 
					{
						out.println("230 User logged in.");
					}
					else if(mes !="akashpass")
					{
						out.println("501 Syntax error in parameters or arguments.");
					}
					else
						out.println("332 Need account for login.");
				}
				else 
				{
					clientSocket.close();
				}
			} 
		}catch (Exception e) {e.printStackTrace();}
	}
}
