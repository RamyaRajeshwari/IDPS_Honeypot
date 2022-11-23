package firewall;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class UNBlock {
	
	public String port;
	public String protocol;
	
	public UNBlock(String num, String pro) {
		this.port=num;
		this.protocol=pro;
		
		try {
			String line;
			Process p = Runtime.getRuntime().exec(
					"netsh advfirewall firewall delete rule name=Block"+pro+num+"");
			BufferedReader bri = new BufferedReader
					(new InputStreamReader(p.getInputStream()));
			BufferedReader bre = new BufferedReader
					(new InputStreamReader(p.getErrorStream()));
			while ((line = bri.readLine()) != null) {
				System.out.println(line);
		
			}
			bri.close();
			while ((line = bre.readLine()) != null) {
				System.out.println(line);
			}
			bre.close();
			p.waitFor();
			System.out.println("Done. rule Deleted");			
		}
		catch (Exception err) {
			err.printStackTrace();
		}
	}
	
}
