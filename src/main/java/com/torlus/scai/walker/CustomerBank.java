package com.torlus.scai.walker;

import static spark.Spark.get;
import static spark.Spark.port;

import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.oidc.client.GoogleOidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.sparkjava.ApplicationLogoutRoute;
import org.pac4j.sparkjava.CallbackRoute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JWSAlgorithm;

public class CustomerBank extends Bank {

	private final static Logger logger = LoggerFactory.getLogger(CustomerBank.class);

	public CustomerBank(int port, String serverBase) {
		this.port = port;
		this.serverBase = serverBase;
		this.identities = new Resource.OfType<>();
		try {
			identities.load("customers.json", Identity.class);
		} catch(Exception ex) {
			ex.printStackTrace();
		}
		port(port);
	}

	
	public void setupOAuth(Config config, String provider) throws Exception {
		this.config = config;
		this.provider = provider;
		
		get("/scai/logout", new ApplicationLogoutRoute(config));
		
		CallbackRoute callback = new CallbackRouteImpl(config, provider);
		get("/scai/callback-" + provider, callback);
		
	}


	public static void main(String args[]) throws Exception {
		final int port = 4567;
		// port(port);

		CustomerBank bank = new CustomerBank(port, "localhost");
		bank.setLabel("Customer Bank");

		OidcConfiguration oidcConf = new OidcConfiguration();
		oidcConf.setClientId(Credentials.GOOGLE_CLIENT_ID);
		oidcConf.setSecret(Credentials.GOOGLE_CLIENT_SECRET);
		oidcConf.setDiscoveryURI("https://accounts.google.com/.well-known/openid-configuration");
		oidcConf.setUseNonce(true);
		oidcConf.setPreferredJwsAlgorithm(JWSAlgorithm.RS256);
		oidcConf.setCallbackUrl("http://" + bank.serverBase + ":" + bank.port + "/scai/callback-google");
		oidcConf.addCustomParam("consent", "prompt");
		GoogleOidcClient client = new GoogleOidcClient(oidcConf);
		client.setCallbackUrl(oidcConf.getCallbackUrl());
		client.setName("scai-client");
		
		Clients clients = new Clients();
		clients.setClients(client);
		
		Config config = new Config();
		config.setClients(clients);
		config.setHttpActionAdapter(new HttpActionAdapterImpl());
				
		try {
			bank.setupCerts("customer-bank");
			bank.setupOAuth(config, "google");
			bank.setupInbox();
			
			bank.setupPaymentRequestHandler();
			
			bank.setupDefaults();
		} catch(Exception ex) {
			ex.printStackTrace();
		}
		
	}
}
