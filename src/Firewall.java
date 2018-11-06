import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class Firewall {
	private static String path;
	private final static Logger LOGGER = Logger.getLogger(Firewall.class.getName()); 
	private static List<Parameter> rules;
	
	public Firewall(String path) {
		Firewall.path = path;
	}
	
	public static void main(String args[]) throws Exception {
		if(args.length != 1 && !args[0].contains("csv")) {
			LOGGER.info("Invalid input argument or file format");
			System.exit(1);
		}
		
		Firewall firewall = new Firewall(args[0]);
		rules = firewall.readCsv(path);
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String line = null;
		System.out.println("Enter packet information comma separated or enter end to exit");
		System.out.println("Input order --> direction,protocol,port,ip_address");
		while(true) {
			line = br.readLine();
			if(line.equalsIgnoreCase("end"))
				break;
			String str[] = line.split(",");
			if(str == null || str.length != 4) {
				LOGGER.info("Invalid packet information. Try again!");
				continue;
			}
			
			boolean accepts = firewall.accept(str[0], str[1], str[2], str[3]);
			System.out.println(accepts);
		}
		
		if(br != null)
			br.close();
	}
	
	private boolean accept(String direction, String protocol, String port, String ip_address) throws Exception {
		for (Parameter input : rules) {
			if (input.getDirection().equalsIgnoreCase(direction) && input.getProtocol().equalsIgnoreCase(protocol)
					&& input.checkPortRange(port) && input.checkIPRange(ip_address))
				return true;
		}
		return false;
	}
	
	private List<Parameter> readCsv(String path) throws Exception {
		List<Parameter> rules = new ArrayList<>();
		BufferedReader br = null;
		Parameter p = null;
		try {
			br = new BufferedReader(new FileReader(path));
			String line;
			while((line = br.readLine()) != null) {
				String str[] = line.split(","); //input order --> direction, protocol, ports, ip_address
				if(str[0].equalsIgnoreCase("diretion"))
					continue;
				else if(str.length != 4) {
					LOGGER.info("Invalid number of input arguments" + Arrays.toString(str));
					System.exit(1);
				}
				
				if(isDirectionValid(str[0]) && isProtocolValid(str[1]))
					p = new Parameter(str[0], str[1], str[2], str[3]);
				else {
					LOGGER.info("Invalid direction or/and protocol");
					System.exit(1);
				}
				
				rules.add(p);
			}
		}
		catch(Exception ex) {
			throw new Exception(ex.getMessage());
		}
		finally {
			if(br != null)
				br.close();
		}
		
		return rules;
	}
	
	private boolean isDirectionValid(String direction) {
		return (direction.equalsIgnoreCase("inbound") || direction.equalsIgnoreCase("outbound"));
	}
	
	private boolean isProtocolValid(String protocol) {
		return (protocol.equalsIgnoreCase("tcp") || protocol.equalsIgnoreCase("udp"));
	}
}

class Parameter {
	String direction;
	String protocol;
	String port;
	String ip_address;

	private static final Pattern PATTERN = Pattern
			.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
	private final static Logger LOGGER = Logger.getLogger(Firewall.class.getName());

	public Parameter(String direction, String protocol, String port, String ip_address) {
		this.direction = direction;
		this.protocol = protocol;
		this.port = port;
		this.ip_address = ip_address;
	}
	
	public String getDirection() {
		return direction;
	}

	public void setDirection(String direction) {
		this.direction = direction;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getPort() {
		return port;
	}

	public void setPort(String port) {
		this.port = port;
	}

	public String getIp_address() {
		return ip_address;
	}

	public void setIp_address(String ip_address) {
		this.ip_address = ip_address;
	}
	
	public long convertToLong(InetAddress ip) {
		byte[] octets = ip.getAddress();
		long ans = 0;
		for (byte octet : octets) {
			ans <<= 8;
			ans |= octet & 0xff;
		}
		return ans;
	}
	
	//https://docs.oracle.com/javase/7/docs/api/java/net/InetAddress.html
	public boolean checkIPRange(String ip_address) throws Exception {
		if(!PATTERN.matcher(ip_address).matches()) {
			LOGGER.info("Invalid IP Address");
			return false;
		}
		String ip = getIp_address();
		if(ip.contains("-")) {
			String split[] = ip.split("-");
			Long lower = convertToLong(InetAddress.getByName(split[0]));
			Long higher = convertToLong(InetAddress.getByName(split[1]));
			Long test = convertToLong(InetAddress.getByName(ip_address));
			
			return (lower <= test && test <= higher);
		}
		else {
			Long value = convertToLong(InetAddress.getByName(ip));
			Long test = convertToLong(InetAddress.getByName(ip_address));
			return value.equals(test);
		}
	}

	public boolean checkPortRange(String test_port) {
		try {
			Integer.parseInt(test_port);
		}
		catch(Exception e) {
			LOGGER.info("Invalid Port");
			return false;
		}
		String port = getPort();
		if(port.contains("-")) {
			String split[] = port.split("-");
			Integer lower = Integer.parseInt(split[0]);
			Integer higher = Integer.parseInt(split[1]);
			Integer test = Integer.parseInt(test_port);
			return (lower <= test && test <= higher);
		}
		else {
			return port.equals(test_port);
		}
	}
}
