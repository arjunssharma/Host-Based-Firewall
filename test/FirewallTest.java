import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class FirewallTest {
	
	private final String path = System.getProperty("user.dir") + "/src/input.csv";
	Firewall fw = new Firewall(path);
	List<Parameter> rules;
	
	@Before
	public void addRules() throws Exception {	 
		rules = fw.readCsv(path);
		Assert.assertNotNull(rules);
		fw.setRules(rules);
	}

	@Test
	public void testCase1Accept_Packet() throws Exception {
		boolean result1 = fw.accept_packet("inbound", "tcp", "80", "192.168.1.2");
		Assert.assertEquals(result1, true);
	}
	
	@Test
	public void testCase2Accept_Packet() throws Exception {
		boolean result2 = fw.accept_packet("inbound", "udp", "53", "192.168.2.1");
		Assert.assertEquals(result2, true);
	}
	
	@Test
	public void testCase3Accept_Packet() throws Exception {
		boolean result3 = fw.accept_packet("outbound", "tcp", "10234", "192.168.10.11");
		Assert.assertEquals(result3, true);
	}
	
	@Test
	public void testCase4Accept_Packet() throws Exception {
		boolean result4 = fw.accept_packet("inbound", "tcp", "81", "192.168.1.2");
		Assert.assertEquals(result4, false);
	}
	
	@Test
	public void testCase5Accept_Packet() throws Exception {
		boolean result5 = fw.accept_packet("inbound", "udp", "24", "52.12.48.92");
		Assert.assertEquals(result5, false);
	}
	
	@Test
	public void testIsDirectionValid() {
		boolean value = fw.isDirectionValid("xyz");
		Assert.assertEquals(value, false);
	}
	
	@Test
	public void testIsProtocolValid() {
		boolean value = fw.isProtocolValid("udp");
		Assert.assertEquals(value, true);
	}
}
