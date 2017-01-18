package com.torlus.scai.walker;

import static spark.Spark.before;
import static spark.Spark.exception;
import static spark.Spark.get;
import static spark.Spark.post;
import static spark.Spark.halt;
import static spark.Spark.redirect;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.TrustManager;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.sparkjava.ApplicationLogoutRoute;
import org.pac4j.sparkjava.CallbackRoute;
import org.pac4j.sparkjava.DefaultHttpActionAdapter;
import org.pac4j.sparkjava.SecurityFilter;
import org.pac4j.sparkjava.SparkWebContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.torlus.scai.walker.Bank.CallbackRouteImpl;
import com.torlus.scai.walker.Bank.ProtectedRoute;
import com.torlus.scai.walker.Bank.ProtectedRouteImpl;
import com.torlus.scai.walker.Bank.ProtectedTemplateViewRoute;
import com.torlus.scai.walker.Bank.ProtectedTemplateViewRouteImpl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import spark.ExceptionHandler;
import spark.ModelAndView;
import spark.Redirect;
import spark.Request;
import spark.Response;
import spark.Route;
import spark.TemplateEngine;
import spark.TemplateViewRoute;
import spark.template.mustache.MustacheTemplateEngine;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class Bank {
	
	public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERT = "-----END CERTIFICATE-----";
	
	public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
	public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
	
	private static final Logger logger = LoggerFactory.getLogger(Bank.class);

	private static final MustacheTemplateEngine templateEngine = new MustacheTemplateEngine();
	
	public static class HttpActionAdapterImpl extends DefaultHttpActionAdapter {
	    @Override
	    public Object adapt(int code, SparkWebContext context) {
	        if (code == HttpConstants.UNAUTHORIZED) {
	            halt(401);
	        } else if (code == HttpConstants.FORBIDDEN) {
	            halt(403);
	        } else {
	            return super.adapt(code, context);
	        }
	        return null;
	    }
	}

	public static class CallbackRouteImpl extends CallbackRoute {
		private String provider;
		
		CallbackRouteImpl(Config config, String provider) {
			super(config);
			this.provider = provider;
		}
		
	    @Override
	    public Object handle(Request request, Response response) throws Exception {
			logger.info("Callback " + provider + " " + System.currentTimeMillis());
			request.attribute("provider", provider);
	    	return super.handle(request, response);
	    }
	}

	public int port;
	public String serverBase;
	
	public Resource.OfType<Identity> identities;
	
	public Config config;
	public String provider;

	
	@FunctionalInterface
	public interface ProtectedRoute {
	    Object handle(String id, Request request, Response response) throws Exception;
	}

	@FunctionalInterface
	public interface ProtectedTemplateViewRoute {
	    ModelAndView handle(String id, Request request, Response response) throws Exception;
	}
	
	public class ProtectedTemplateViewRouteImpl implements TemplateViewRoute {
		private ProtectedTemplateViewRoute protectedRoute;
		
		public ProtectedTemplateViewRouteImpl(ProtectedTemplateViewRoute route) {
			this.protectedRoute = route;
		}

		@Override
		public ModelAndView handle(Request request, Response response) throws Exception {
			SparkWebContext context = new SparkWebContext(request, response);
			ProfileManager<CommonProfile> manager = new ProfileManager<CommonProfile>(context);				
			Optional<CommonProfile> profile = manager.get(true);
			if (profile.isPresent()) {
				String pid = profile.get().getId();
				
				//System.out.println(identities.getClass().getName());
				//System.out.println(identities.all().getClass().getName());
				//System.out.println(identities.all().get(0).getClass().getName());
				
				for(Object o: identities.all()) {
					Identity id = (Identity)o;
					if (id.provider_id.equals(pid))
						return protectedRoute.handle(id.id, request, response);
				}
			}
			halt(403);
			return null;
		}
		
	}
	
	public class ProtectedRouteImpl implements Route {
		
		private ProtectedRoute protectedRoute;
		
		public ProtectedRouteImpl(ProtectedRoute route) {
			this.protectedRoute = route;
		}
		
		@Override
		public Object handle(Request request, Response response) throws Exception {
			SparkWebContext context = new SparkWebContext(request, response);
			ProfileManager<CommonProfile> manager = new ProfileManager<CommonProfile>(context);				
			Optional<CommonProfile> profile = manager.get(true);
			if (profile.isPresent()) {
				String pid = profile.get().getId();
				
				//System.out.println(identities.getClass().getName());
				//System.out.println(identities.all().getClass().getName());
				//System.out.println(identities.all().get(0).getClass().getName());
				
				for(Object o: identities.all()) {
					Identity id = (Identity)o;
					if (id.provider_id.equals(pid))
						return protectedRoute.handle(id.id, request, response);
				}
			}
			halt(403);
			return null;
		}
	}

	public void addProtectedRoute(String path, ProtectedRoute route) {
		String clientName = config.getClients().findAllClients().get(0).getName();
		before(path, new SecurityFilter(config, clientName));

		get(path, new ProtectedRouteImpl(route));
	}
	
	public void addProtectedTemplateViewRoute(String path, ProtectedTemplateViewRoute route, TemplateEngine engine) {
		String clientName = config.getClients().findAllClients().get(0).getName();
		before(path, new SecurityFilter(config, clientName));

		get(path, new ProtectedTemplateViewRouteImpl(route), engine);
	}

	public void setupDefaults() {
		
		get("/", (req, res) -> {
			Map<String, String> map = new HashMap<>();
			map.put("timestamp", new Date().toString());
			return new ModelAndView(map, "bank-index.mustache");
		}, templateEngine);

		redirect.get("/scai", "/scai/");
		
		get("/scai/", (req, res) -> {
			Map<String, String> map = new HashMap<>();
			map.put("timestamp", new Date().toString());
			return new ModelAndView(map, "bank-scai-index.mustache");
		}, templateEngine);

		exception(Exception.class, new ExceptionHandler() {
			@Override
			public void handle(Exception exception, Request request, Response response) {
				exception.printStackTrace();
				response.body("Exception " + System.currentTimeMillis());
			}
		});

	}
	
	
	protected Certificate cacert;
	protected Certificate cert;
	protected RSAPrivateCrtKey key;
	
	protected String location;
	
	public void setLabel(String label) {
		location = label;
	}
	
	public void setupCerts(String keystore) throws Exception {
		KeyStore caks = KeyStore.getInstance("JKS");
		caks.load(new FileInputStream(new File("ca.jks")), "scai".toCharArray());
		cacert = caks.getCertificate("ca");
		
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream(new File(keystore + ".p12")), "scai".toCharArray());
		cert = ks.getCertificate(keystore);
		logger.info(cert.toString());
		String pem = Base64.getEncoder().encodeToString(cert.getEncoded());
		String pemFinal = BEGIN_CERT + "\n" + pem + "\n" + END_CERT + "\n";
		get("/scai/pub", (req, res) -> {
			return pemFinal; 
		});
		key = (RSAPrivateCrtKey)ks.getKey(keystore, "scai".toCharArray());
		
		get("/scai/identities/:id/pub", (req, res) -> {
			Identity id = identities.find(req.params("id"));
			if (id == null || id.certificate == null || id.certificate.length() == 0)
				return 404;
			return BEGIN_CERT + "\n" + id.certificate + "\n" + END_CERT + "\n"; 
		});
	}


	public void setupInbox() throws Exception {
		post("/scai/inbox", (request, response) -> { 
			String msg = request.queryParams("jwt");
			Map<String, String> props = ScaiTools.verifySigner(msg, cert, logger);
			
			String issuer = props.get("iss");
			logger.info("iss:" + issuer);
			issuer = issuer.substring(issuer.lastIndexOf('/') + 1);
			
			String target = props.get("aud");
			int p = target.indexOf("/identities/");
			if (p > 0)
				target = target.substring(0, p + 1);
			
			Identity idn = identities.find(issuer);
			if (idn == null || idn.private_key == null || idn.private_key.length() == 0) {
				response.status(400);
				return null;
			}
			PKCS8EncodedKeySpec ksp = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(idn.private_key)); 
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey pk = kf.generatePrivate(ksp);

			Claims vcls = Jwts.parser().setSigningKey(pk).parseClaimsJws(msg).getBody();
			logger.info("verifiedClaims:" + vcls.toString());
			
			SignatureAlgorithm alg = SignatureAlgorithm.RS256;
			Date now = new Date();
			JwtBuilder builder = Jwts.builder()
					.setHeaderParam("x5u", "http://" + serverBase + ":" + port + "/scai/pub")
					.setIssuer("http://" + serverBase + ":" + port + "/scai/")
					.setIssuedAt(now)
					.setSubject(vcls.getSubject())
					.setAudience(vcls.getAudience())
					.signWith(alg, key);
			builder.claim("scai_name", idn.name);
			ScaiTools.embed(builder, msg);
			
			String rjwt = builder.compact();
			String rbody = rjwt.substring(rjwt.indexOf('.') + 1, rjwt.lastIndexOf('.'));
			logger.info(new String(Base64.getDecoder().decode(rbody)));

			Map<String, String> map = new HashMap<>();
			map.put("location", location);
			map.put("jwt", rjwt);
			map.put("pp", ScaiTools.prettyPrint(rjwt));
			map.put("redirect", target + vcls.getSubject());
			ScaiTools.prettify(map);
			return new ModelAndView(map, "redirect.mustache");

		}, templateEngine);
	}
	
	@SuppressWarnings({"unchecked", "restriction"})
	public void setupPaymentRequestHandler() throws Exception {
		post("/scai/payment-request", (request, response) -> { 
			String msg = request.queryParams("jwt");
			response.cookie("/scai/", "scai-request", msg, 30*60, false);
			// response.redirect("/scai/payment-request-ui");
    		Map<String, String> map = new HashMap<>();
    		map.put("location", location);
    		map.put("pp", ScaiTools.prettyPrint(msg));
    		ScaiTools.prettify(map);
			return new ModelAndView(map, "bank-scai-payment-request-index.mustache");
		}, templateEngine);
		
		addProtectedTemplateViewRoute("/scai/payment-request-ui", (id, request, response) -> {
			String msg = request.cookie("scai-request");
			logger.info("cookie=" + msg);
			Map<String, String> props = ScaiTools.verifySigner(msg, cacert, logger);
			
			boolean generate = false;
			Identity idn = identities.find(id);
            if (idn.certificate == null || idn.certificate.length() == 0) {
            	generate = true;
            } else {
            	try {
	                CertificateFactory cf = CertificateFactory.getInstance("X.509");
	                X509Certificate crt = 
	                		(X509Certificate)cf.generateCertificate(
	                				new ByteArrayInputStream(
	                						Base64.getDecoder().decode(idn.certificate)));
	                crt.checkValidity();
                } catch(Exception ex) {
                	generate = true;
                }
            }
			
            if (generate) {
	            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	            kpg.initialize(2048);
	            KeyPair kp = kpg.generateKeyPair();
	            
	            X509CertInfo info = new X509CertInfo();
	            Date from = new Date();
	            Date to = new Date(from.getTime() + 24L * 60L * 60L * 1000L);
	            
				CertificateValidity interval = new CertificateValidity(from, to);
	            BigInteger sn = new BigInteger(64, new SecureRandom());

	            info.set(X509CertInfo.VALIDITY, interval);
	            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
	            info.set(X509CertInfo.ISSUER, new X500Name("CN=customer-bank"));
	            info.set(X509CertInfo.SUBJECT, new X500Name("CN=" + id));
	            info.set(X509CertInfo.KEY, new CertificateX509Key(kp.getPublic()));
	            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
	            AlgorithmId algo = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);
	            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
	           
	            X509CertImpl cert = new X509CertImpl(info);
	            cert.sign(key, algo.toString());
	            
	            idn.certificate = Base64.getEncoder().encodeToString(cert.getEncoded());
	            idn.private_key = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
	            identities.save();
            }
    		Map<String, String> map = new HashMap<>();
    		map.put("location", location);
    		map.put("remote_name", props.get("scai_name"));
    		map.put("name", idn.name);
    		
            byte[] inner = Base64.getDecoder().decode(ScaiTools.extractBody(props));
    		ObjectMapper objectMapper = new ObjectMapper();
    		Map<String, String> innerProps = objectMapper.readValue(inner, HashMap.class);
    		
    		String status = request.queryParams("accept");
    		if (status != null) {
    			status = "accepted";
    		} else {
    			status = request.queryParams("decline");
    			if (status != null) {
    				status = "declined"; 
    			}
    		}
    		map.put("validated", "" + (status != null));
    		map.put("id", innerProps.get("scai_id"));
    		map.put("amount", innerProps.get("scai_amount"));
    		
    		if (status != null) {
    			PKCS8EncodedKeySpec ksp = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(idn.private_key)); 
    			KeyFactory kf = KeyFactory.getInstance("RSA");
    			PrivateKey pk = kf.generatePrivate(ksp);

    			SignatureAlgorithm alg = SignatureAlgorithm.RS256;
    			Date now = new Date();
    			JwtBuilder builder = Jwts.builder()
    					.setHeaderParam("x5u", "http://" + serverBase + ":" + port + "/scai/identities/" + id + "/pub")
    					.setIssuer("http://" + serverBase + ":" + port + "/scai/identities/" + id)
    					.setIssuedAt(now)
    					.setSubject("payment-response")
    					.setAudience(innerProps.get("iss"))
    					.signWith(alg, pk);
        		builder.claim("scai_id", innerProps.get("scai_id"));
        		builder.claim("scai_amount", innerProps.get("scai_amount"));
        		builder.claim("scai_callback", innerProps.get("scai_callback"));
        		builder.claim("scai_status", status);    			
    			ScaiTools.embed(builder, msg);
    			
    			String rjwt = builder.compact();
    			String rbody = rjwt.substring(rjwt.indexOf('.') + 1, rjwt.lastIndexOf('.'));
    			logger.info(new String(Base64.getDecoder().decode(rbody)));

    			map.put("jwt", rjwt);
    			map.put("pp", ScaiTools.prettyPrint(rjwt));
    			map.put("redirect", "/scai/inbox");
    			ScaiTools.prettify(map);
    			return new ModelAndView(map, "redirect.mustache");
    		}
    		ScaiTools.prettify(map);
            return new ModelAndView(map, "bank-scai-payment-request.mustache");
		}, templateEngine);		
	}

	@SuppressWarnings("unchecked")
	public void setupPaymentResponseHandler() throws Exception {
		post("/scai/payment-response", (request, response) -> { 
			String msg = request.queryParams("jwt");
			Map<String, String> props = ScaiTools.verifySigner(msg, cacert, logger);
			
            byte[] inner = Base64.getDecoder().decode(ScaiTools.extractBody(props));
    		ObjectMapper objectMapper = new ObjectMapper();
    		Map<String, String> innerProps = objectMapper.readValue(inner, HashMap.class);
						
			String target = innerProps.get("aud");
			target = target.substring(target.lastIndexOf('/') + 1);
			logger.info("response: target=" + target);
			
			Identity idn = identities.find(target);
			if (idn == null || idn.private_key == null || idn.private_key.length() == 0) {
				response.status(400);
				return null;
			}
			PKCS8EncodedKeySpec ksp = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(idn.private_key)); 
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey pk = kf.generatePrivate(ksp);
  
			SignatureAlgorithm alg = SignatureAlgorithm.RS256;
			Date now = new Date();
			JwtBuilder builder = Jwts.builder()
					.setHeaderParam("x5u", "http://" + serverBase + ":" + port + "/scai/identities/" + target + "/pub")
					.setIssuer("http://" + serverBase + ":" + port + "/scai/identities/" + target)
					.setIssuedAt(now)
					.setSubject(innerProps.get("sub"))
					.setAudience(innerProps.get("aud"))
					.signWith(alg, pk);
			builder.claim("scai_name", idn.name);
    		builder.claim("scai_id", innerProps.get("scai_id"));
    		builder.claim("scai_amount", innerProps.get("scai_amount"));
    		builder.claim("scai_callback", innerProps.get("scai_callback"));
    		builder.claim("scai_status", innerProps.get("scai_status"));
			ScaiTools.embed(builder, msg);
			
			String rjwt = builder.compact();
			String rbody = rjwt.substring(rjwt.indexOf('.') + 1, rjwt.lastIndexOf('.'));
			logger.info(new String(Base64.getDecoder().decode(rbody)));

			// response.cookie("/scai/", "scai-request", rjwt, 30*60, false);
			String callback = innerProps.get("scai_callback");
			logger.info("redirecting to:" + callback);

			Map<String, String> map = new HashMap<>();
			map.put("location", location);
			map.put("jwt", rjwt);
			map.put("pp", ScaiTools.prettyPrint(rjwt));
			map.put("redirect", callback);
			ScaiTools.prettify(map);
			return new ModelAndView(map, "redirect.mustache");
		}, templateEngine);

	}
}
