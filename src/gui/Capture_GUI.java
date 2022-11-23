package gui;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.NetworkInterface;
import java.util.Date;
import javax.swing.*;
import firewall.BlockPort;
import firewall.UNBlock;
import honeypotServer.HoneypotServer;
import jpcap.*;
import java.awt.event.*;
import java.io.*;
import java.awt.*;


//ACTION//

public class Capture_GUI {
	JFrame MainWindow = new JFrame("INTRUSION DETECTION v1.o");
	public static JTextArea TA_OUTPUT = new JTextArea();
	public static JTextArea TA_PORT = new JTextArea();
	JTextField TF_SelectInterface = new JTextField();
	JTextField TF_PortBlock = new JTextField();
	JTextField TF_PortUNBlock = new JTextField();
	JButton B_CAPTURE = new JButton("CAPTURE");
	JButton B_STOP = new JButton("STOP");
    JButton B_SELECT = new JButton("SELECT"); 
    JButton B_LIST = new JButton("LIST");
    //JButton B_SAVE = new JButton("SAVE");
	jpcap.NetworkInterface[] NETWORK_INTERFACES; 
	private static String ADDRE = null;
	private static String new_ip = null;
	private static final String DEFAULT_LOG_DIR = null;
	JLabel L_HACKERCONNECTED=new JLabel();
	JLabel L_HACKERCONNECTED1=new JLabel();
	JComboBox comboBox = new JComboBox ();
	JComboBox comboBox_UN = new JComboBox ();
	int COUNTER = 0;
	int INDEX = 0;
	CaptureThread CAPTAIN;
    JpcapCaptor CAP;
	private boolean CaptureState;
	
	public static void main(String args[])
	{
	   new Capture_GUI();
	}
	
	public Capture_GUI()
	{
	    BuildGUI();
	    //DisableButtons();
	}
	
	public void BuildGUI()
	{

	   MainWindow.setSize(765,500);
	   MainWindow.setLocation(200,200);
	   MainWindow.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
	   MainWindow.getContentPane().setLayout(null);

	   TA_OUTPUT.setEditable(false);
	   TA_OUTPUT.setFont(new Font("Monospaced", 0, 12));
	   TA_OUTPUT.setForeground(new Color(0, 0, 153));
	   TA_OUTPUT.setLineWrap(true);

	   B_CAPTURE.setBackground(new Color(255, 0, 0));
	   B_CAPTURE.setForeground(new Color(255, 255, 255));
	   B_CAPTURE.setMargin(new Insets(0, 0, 0, 0));
	   B_CAPTURE.addActionListener(new ActionListener()
	   {
	      public void actionPerformed(ActionEvent X)
	      {
	        Action_B_CAPTURE(X);
	      }
	    });

	   MainWindow.getContentPane().add(B_CAPTURE);
	   B_CAPTURE.setBounds(10, 310, 130, 25);

	   B_STOP.setBackground(new Color(0, 0, 0));
	   B_STOP.setForeground(new Color(255, 255, 255));
	   B_STOP.setMargin(new Insets(0, 0, 0, 0));
	   B_STOP.addActionListener(new ActionListener()
	   {
	      public void actionPerformed(ActionEvent X)
	      { 
	          Action_B_STOP(X);
	      }      
	   });

	   MainWindow.getContentPane().add(B_STOP);
	   B_STOP.setBounds(145, 310, 110, 25);

	   B_SELECT.setBackground(new Color(0, 0, 0));
	   B_SELECT.setForeground(new Color(255, 255, 255));
	   B_SELECT.setMargin(new Insets(0, 0, 0, 0));
	   B_SELECT.addActionListener(new ActionListener()
	   {
	    public void actionPerformed(ActionEvent X)
	    {
	      Action_B_SELECT(X);
	    }
	   });

	   MainWindow.getContentPane().add(B_SELECT);
	   B_SELECT.setBounds(0, 388, 75, 20);


	   B_LIST.setBackground(new Color(0, 0, 0));
	   B_LIST.setForeground(new Color(255,255,255));
	   B_LIST.setMargin(new Insets(0, 0, 0, 0));
	   B_LIST.addActionListener(new ActionListener()
	   {
	    public void actionPerformed(ActionEvent X)
	    {
	      Action_B_LIST(X);
	    }
	   });
	   MainWindow.getContentPane().add(B_LIST);
	   B_LIST.setBounds(0, 410, 75, 20);
	  

	   /*B_SAVE.setBackground(new Color(0, 0, 0));
	   B_SAVE.setForeground(new Color(255, 255, 255));
	   B_SAVE.setMargin(new Insets(0, 0, 0, 0));
	   B_SAVE.addActionListener(new ActionListener()
	   {
	    public void actionPerformed(ActionEvent X)
	    {
	      Action_B_SAVE(X);
	    }
	   });
	   MainWindow.getContentPane().add(B_SAVE);
	   B_SAVE.setBounds(100, 340, 75, 25);*/
	   
	   
	    TF_SelectInterface.setForeground(new Color(255,0,0));
	    TF_SelectInterface.setHorizontalAlignment(SwingConstants.CENTER);
	    MainWindow.getContentPane().add(TF_SelectInterface);
	    TF_SelectInterface.setBounds(3, 364, 70, 20);
	    
	   MainWindow.setVisible(true);
	}
	
	public void Action_B_CAPTURE(ActionEvent X){
		TA_OUTPUT.setText("");
		CaptureState=true;
		CapturePackets();
	}
	
	public void Action_B_LIST(ActionEvent X){
		ListNetworkInterfaces( );
		TF_SelectInterface.requestFocus() ;
	}
	
	public void Action_B_SELECT(ActionEvent X){
		ChooseInterface() ;
	}
	
	public void Action_B_STOP(ActionEvent X){
		CaptureState = false;
		CAPTAIN.finished() ;
	}
	
	public void Action_B_PORT(ActionEvent X)
	{
		PortScanner();
	}
	
	/*public void Action_B_SAVE(ActionEvent X)
	{
		//CaptureData();
		SaveCapture();
	}*/
	
	public void Action_B_SAVELOCAL(ActionEvent X){
		//CaptureData() ;
		CaptureDataLocal();
	}
	
	public void Action_B_PORTBLOCK(ActionEvent X)
	{
		BlockPortSytem();
	}
	
	public void Action_B_PORTUNBLOCK(ActionEvent X) {
		UNBlockPortSytem();
	}
	
	public void Action_B_HONEYSTART(ActionEvent X) throws IOException
	{
		HONEYSTART() ;
	}
	
	public void Action_B_HONEYSTOP(ActionEvent X) throws IOException
	{
		//new HoneypotServer().StopServer();
	}
	
	public void Action_B_HONEYSTARTIRC(ActionEvent X) throws IOException
	{
		HONEYSTARTIRC();
	}
	
	public void Action_B_HONEYSTOPIRC(ActionEvent X)
	{
		
	}
	
	
	//FUNCTIONS//
	
	public void ListNetworkInterfaces(){
	
		try{
		NETWORK_INTERFACES = JpcapCaptor.getDeviceList();
		
		TA_OUTPUT.setText("");
			for(int i=0; i< NETWORK_INTERFACES.length;i++){
			
				TA_OUTPUT.append("\n----------------------------------Interface"+i+
						          "Info----------------------------------");
				TA_OUTPUT.append("\nInterface Number: "+i);
				TA_OUTPUT.append("\nDescription :"+NETWORK_INTERFACES[i].name+"("+
			                     NETWORK_INTERFACES[i].description);
				TA_OUTPUT.append("\nDataLink Name"+NETWORK_INTERFACES[i].datalink_name+"("+
						         NETWORK_INTERFACES[i].datalink_description+")");
				
				NetworkInterfaceAddress [] INT = NETWORK_INTERFACES[i].addresses;
				
				TA_OUTPUT.append("\nIP Address1 : "+INT[0].address);
				TA_OUTPUT.append("\nSubnet : "+INT[0].subnet);
			
				ADDRE = INT[0].address.toString();
				
				System.out.println(ADDRE);
				new_ip = ADDRE.replaceAll("/","");
				System.out.println(new_ip);
			}
			COUNTER++;
		
	}
		catch(Exception e){System.out.println(e);}}
	//-----------------------------------------------------//
	
	public void ChooseInterface() {
		int Temp = Integer.parseInt(TF_SelectInterface.getText());
			if(Temp > -1 && Temp < COUNTER) {
				INDEX= Temp;
				//EnableButtons();
			}
			else {
			
			}
		TF_SelectInterface.setText("");
	}
	
	//-----------------------------------------------------//
	public void CapturePackets()
	{
		CAPTAIN=new CaptureThread() {
		
			@Override
			public Object construct() {
			
			TA_OUTPUT.setText("\nNow capturing on interface :"+INDEX+"... "+
		                      "\n----------------------------------"
					           +"----------------------------------\n\n");
				try {
					CAP = JpcapCaptor.openDevice(NETWORK_INTERFACES[INDEX],65535, false, 20);
					//CAP.setFilter("ip", true);
						while(CaptureState) {
						CAP.processPacket(1, new PacketContents());
						}
					
					CAP.close();
				} catch (Exception e) {
					// TODO: handle exception
					System.out .println(e);
				}
				return 0;
			}
		public void finished(){
			this.interrupt();
		}
		};
				CAPTAIN.start();
	}
	
	//-----------------------------------------------------//
	public void PortScanner() {
	
		try {
		
			String command = "netstat -a";
			System.out.println(command) ;
			String line;
			Process p = Runtime.getRuntime().exec(command) ;
			BufferedReader bri = new BufferedReader
			  (new InputStreamReader(p.getInputStream())) ;
			BufferedReader bre = new BufferedReader
			  (new InputStreamReader(p.getErrorStream())) ;
			while ((line = bri.readLine()) != null) {
				TA_PORT.append (line+"\n") ;
			}
			bri.close();
			while ((line = bre.readLine()) != null) {
				TA_PORT.append(line+"\n");
			}
			bre.close();
			p.waitFor();
		}
		catch (Exception err) {
			err.printStackTrace();
		}
	}
	
	//-----------------------------------------------------//
	/*public void SaveCapture()
	{
		Thread t1 = new Thread( new Runnable(){
			@Override
	
			public void run() {
				// TODO Auto-generated method stub
	
				for (int i=1; i <=3; i++) {
					System.out.println("Saving from SaveThread class..... ");
					CaptureData();
					try{
						Thread.sleep(10000) ;
					}catch (Exception ex) {
						ex.printStackTrace();
					}
				}
			}
		});
		t1.start();
	}*/
	
	//-----------------------------------------------------//
	public void BlockPortSytem()
	{
	
		String num = TF_PortBlock.getText().toString();
		String protocol = (String) comboBox.getSelectedItem();
		
		BlockPort block = new BlockPort(num, protocol) ;
	}
	// UNBLOCK FUNCTION//
	
	public void UNBlockPortSytem() {
		String num = TF_PortUNBlock.getText().toString();
		String protocol = (String) comboBox_UN.getSelectedItem();
	
		UNBlock unblock = new UNBlock(num, protocol) ;
	}
	//HONETPOT-on FTP//
	
	
	public void HONEYSTART()
	{
	
		Thread honeyftp = new Thread(new Runnable() {
		
			@Override
			public void run() {
				// TODO Auto-generated method stub
				
				try {
					new HoneypotServer().runServer();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});
		honeyftp.start();
		// HoneypotServer h1 = new HoneypotServer();
		JOptionPane. showMessageDialog(MainWindow,"HoneyServer Started");
	}
	
	//HONETPOT-on IRC//
	public void HONEYSTARTIRC()
	{
	
		Thread t2 = new Thread(new Runnable() {
			@Override
			public void run() {
			// TODO Auto-generated method stub
			
				try {
					new HoneypotServer().runServer();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
	
		});
		t2.start();
		JOptionPane. showMessageDialog(MainWindow, "HoneyServerIRC Started");
	}
	
			 
	
	/*public static void CaptureData()
	{
		String CaptureData=TA_OUTPUT.getText();
		
		try {
		
			MongoClient mongoclient = new MongoClient("localhost",27017);
			DB db = mongoclient.getDB( " tep" );
			System.out.println("Connect to database successfully");
			
			//a file into mongo db using grid fs
			DBCollection coll = db.getCollection("mycol");
			
			System.out.println("capture data" + CaptureData);
			BasicDBObject document = new BasicDBObject();
			document. put("first", CaptureData);
			
			coll.insert (document) ;
			System. out .println("DONE");
		} catch (Exception e) {
			// T000: handle exception
			e.printStackTrace();
		}
	}*/
	
	// saving data on local machine
	
	public static void CaptureDataLocal()
	{
	
		String CaptureData=TA_OUTPUT.getText();
		try {File Data = new File(DEFAULT_LOG_DIR,+new Date().getDate()+".log");
		
			FileOutputStream datastream = new FileOutputStream(Data);
			PrintStream out = new PrintStream(datastream);
			out. print(CaptureData) ;
			out.close();
			datastream.close();
			System.out.println( "Saving........from CaptureData function");
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
	}
	
	//data in xml formate
	public static void CaptureDataXML() 
	{
		String CaptureData=TA_OUTPUT.getText();
	
		try {
			File Data = new File("OutPut.txt");
			FileOutputStream datastream = new FileOutputStream(Data);
			PrintStream out = new PrintStream(datastream) ;
			out .print(CaptureData) ;
		
			out .close();
			datastream.close();
			System. out .println("Saving........from CaptureData function");
	
		} catch (Exception e) {
			//TOD0: handle exception
			e.printStackTrace();
		}
	}
	
	//no of connection//
	public void setNumberConnections(int newNum) {
		System.out.println("reached here");
		
		L_HACKERCONNECTED.setText("Hackers connected: " + newNum);
	}
	
	public void setNumberConnectionsIRC(int newNum) {
		System.out.println("reached here");
	
		L_HACKERCONNECTED1.setText("Hackers connected: " + newNum);
	}
	
}
