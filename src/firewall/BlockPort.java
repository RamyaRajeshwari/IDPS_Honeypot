package firewall;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class BlockPort {

	public String port;
	public String protocol;
	public BlockPort (String num, String pro) {
		this.port = num;
		this.protocol = pro;
		
		try {
			String line;
			Process p = Runtime.getRuntime().exec(
					"netsh advfirewall firewall add rule name=Block"+pro+num+
					"protocol="+pro+ "dir=in localport="+num+ 
					"action=block");
			BufferedReader bri = new BufferedReader
					(new InputStreamReader(p.getInputStream()));
			BufferedReader bre = new BufferedReader
					(new InputStreamReader(p.getErrorStream()));
			while ((line = bri.readLine()) != null) {
				System.out.println(line);
			}
			bri.close();
			while ((line = bri.readLine()) != null) {
				System.out.println(line);
			}
			bre.close();
			p.waitFor();
			System.out.println("Done. rule set");
		}
		catch (Exception err) {
			err.printStackTrace();
		}
	}

}
