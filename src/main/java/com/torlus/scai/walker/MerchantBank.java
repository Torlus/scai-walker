package com.torlus.scai.walker;

import static spark.Spark.port;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MerchantBank extends Bank {
	private final static Logger logger = LoggerFactory.getLogger(MerchantBank.class);
	
	public MerchantBank(int port, String serverBase) {
		this.port = port;
		this.serverBase = serverBase;
		this.identities = new Resource.OfType<>();
		try {
			identities.load("merchants.json", Identity.class);
		} catch(Exception ex) {
			ex.printStackTrace();
		}
		port(port);
	}
	
	public static void main(String args[]) throws Exception {
		final int port = 4568;

		MerchantBank bank = new MerchantBank(port, "localhost");
		bank.setLabel("Merchant Bank");
		
		try {
			bank.setupCerts("merchant-bank");
			bank.setupInbox();
			
			bank.setupPaymentResponseHandler();
			
			bank.setupDefaults();
			
		} catch(Exception ex) {
			ex.printStackTrace();
		}
	}
}
